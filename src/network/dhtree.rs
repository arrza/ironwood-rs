use super::{
    core::Core,
    crypto::{PrivateKeyBytes, PublicKeyBytes, SignatureBytes, PUBLIC_KEY_SIZE, SIGNATURE_SIZE},
    pathfinder::{PathTraffic, Pathfinder},
    peers::{Peer, PeerId, PEER_TIMEOUT},
    wire::{encode_path, Decode, Encode, WireDecodeError},
};
use crate::types::PeerPort;
use byteorder::{BigEndian, ReadBytesExt};
use futures::{future::BoxFuture, FutureExt};
use integer_encoding::{VarInt, VarIntReader};
use log::{debug, error};
use serde::{Deserialize, Serialize};
use std::{
    cmp,
    collections::{HashMap, HashSet},
    fmt,
    io::{Cursor, Read},
    sync::{
        atomic::{self, AtomicBool, AtomicU64},
        Arc, Mutex, RwLock, Weak,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub const TREE_TIMEOUT_SECS: u64 = 60 * 60;
pub const TREE_TIMEOUT: Duration = Duration::from_secs(TREE_TIMEOUT_SECS); // TODO: figure out what makes sense
pub const TREE_ANNOUNCE: Duration = Duration::from_secs(TREE_TIMEOUT_SECS / 2);
pub const TREE_THROTTLE: Duration = Duration::from_secs(TREE_TIMEOUT_SECS / 4); // TODO: use this to limit how fast seqs can update
pub const WAIT_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Debug, Serialize, Deserialize)]
pub struct DebugSelfInfo {
    pub key: PublicKeyBytes,
    pub root: PublicKeyBytes,
    pub coords: Vec<u64>,
    #[serde(with = "humantime_serde")]
    updated: SystemTime,
}

#[derive(Debug)]
pub struct DebugPeerInfo {
    pub key: PublicKeyBytes,
    pub root: PublicKeyBytes,
    pub coords: Vec<u64>,
    pub port: u64,
    pub updated: SystemTime,
    pub priority: u8,
    pub remote_addr: String,
}

#[derive(Debug)]
pub struct DebugDHTInfo {
    pub key: PublicKeyBytes,
    pub port: u64,
    pub rest: u64,
}

#[derive(Debug)]
pub struct DebugPathInfo {
    pub key: PublicKeyBytes,
    pub path: Vec<u64>,
}

#[derive(Debug)]
struct UpdateData {
    expired: HashMap<PublicKeyBytes, TreeExpiredInfo>,
    hseq: u64,
    wait: bool,
}

#[derive(Debug, Clone)]
pub struct Dhtree {
    core: Weak<Core>,
    pub(super) pathfinder: Arc<Pathfinder>,
    tinfos: Arc<RwLock<HashMap<PeerId, TreeInfo>>>,
    dinfos: Arc<RwLock<HashMap<DhtMapKey, Arc<DhtInfo>>>>,
    self_info: Arc<RwLock<Option<TreeInfo>>>, // 'self' is a reserved keyword in Rust, so renamed 'self' to 'self_info'.
    parent: Arc<RwLock<PeerId>>,
    prev: Arc<RwLock<Option<Arc<DhtInfo>>>>,
    next: Arc<RwLock<Option<Arc<DhtInfo>>>>,
    dkeys: Arc<RwLock<HashMap<Arc<DhtInfo>, PublicKeyBytes>>>,
    seq: Arc<AtomicU64>,
    bwait: Arc<AtomicBool>,
    btimer: Arc<AtomicBool>,
    update_data: Arc<Mutex<UpdateData>>,
}

#[derive(Debug)]
pub struct TreeExpiredInfo {
    seq: u64,
    time: SystemTime, // Rust equivalent of time.Time in Go
}

impl Dhtree {
    pub fn new(core: Weak<Core>) -> Arc<Self> {
        let dhtree = Arc::new_cyclic(|weak_dhtree| {
            let pathfinder = Pathfinder::new(weak_dhtree.clone());
            Dhtree {
                core,
                pathfinder: Arc::new(pathfinder),
                tinfos: Arc::new(RwLock::new(HashMap::new())),
                dinfos: Arc::new(RwLock::new(HashMap::new())),
                self_info: Arc::new(RwLock::new(None)),
                parent: Arc::new(RwLock::new(PeerId::nil())),
                prev: Arc::new(RwLock::new(None)),
                next: Arc::new(RwLock::new(None)),
                dkeys: Arc::new(RwLock::new(HashMap::new())),
                seq: Arc::new(AtomicU64::new(
                    UNIX_EPOCH.elapsed().unwrap().as_nanos() as u64
                )),
                bwait: Arc::new(AtomicBool::new(false)),
                btimer: Arc::new(AtomicBool::new(true)),
                update_data: Arc::new(Mutex::new(UpdateData {
                    expired: HashMap::new(),
                    hseq: 0,
                    wait: false,
                })),
            }
        });
        dhtree
    }

    pub fn init(&self) {
        self._fix();
    }

    pub fn core(&self) -> Arc<Core> {
        self.core.upgrade().unwrap()
    }

    pub async fn get_dht(&self) -> Vec<DebugDHTInfo> {
        let mut infos = Vec::new();
        debug!("dinfos: {}", self.dinfos.read().unwrap().len());
        for (_, dinfo) in self.dinfos.read().unwrap().iter() {
            let mut info = DebugDHTInfo {
                key: dinfo.key.clone(),
                port: 0,
                rest: 0,
            };
            if !dinfo.peer.is_nil() {
                if let Some(peer) = self.core().peers.get_peer(dinfo.peer) {
                    info.port = peer.port;
                }
            }
            if !dinfo.rest.is_nil() {
                if let Some(rest) = self.core().peers.get_peer(dinfo.rest) {
                    info.rest = rest.port;
                }
            }
            infos.push(info);
        }
        infos
    }

    pub async fn get_self(&self) -> DebugSelfInfo {
        let coords: Vec<_> = self
            .self_info
            .read()
            .unwrap()
            .as_ref()
            .unwrap()
            .hops
            .iter()
            .map(|h| h.port)
            .collect();
        let info = DebugSelfInfo {
            key: self.core().crypto.public_key.clone(),
            root: self
                .self_info
                .read()
                .unwrap()
                .as_ref()
                .unwrap()
                .root
                .clone(),
            coords,
            updated: self.self_info.read().unwrap().as_ref().unwrap().time,
        };
        info
    }

    pub async fn get_peers(&self) -> Vec<DebugPeerInfo> {
        let mut infos = Vec::new();
        for (id, tinfo) in self.tinfos.read().unwrap().iter() {
            if let Some(peer) = self.core().peers.get_peer(*id) {
                let info = DebugPeerInfo {
                    key: peer.key.clone(),
                    root: tinfo.root.clone(),
                    coords: tinfo.hops.iter().map(|h| h.port).collect(),
                    port: peer.port,
                    updated: tinfo.time,
                    priority: peer.prio.load(atomic::Ordering::Relaxed),
                    remote_addr: peer.remote_addr.clone(),
                };
                infos.push(info);
            }
        }
        infos
    }

    pub async fn get_paths(&self) -> Vec<DebugPathInfo> {
        let mut paths = Vec::new();
        for (key, path) in self.pathfinder.get_paths().iter() {
            let info = DebugPathInfo {
                key: key.clone(),
                path: path.path.clone(),
            };
            paths.push(info);
        }
        paths
    }

    fn _send_tree(&self) {
        for pid in self.tinfos.read().unwrap().keys() {
            if let Some(p) = self.core().peers.get_peer(*pid) {
                p.send_tree(self.self_info.read().unwrap().as_ref().unwrap())
                    .unwrap();
            }
        }
    }

    // update adds a treeInfo to the spanning tree
    // it then fixes the tree (selecting a new parent, if needed) and the dht (restarting the bootstrap process)
    // if the info is from the current parent, then there's a delay before the tree/dht are fixed
    //
    //	that prevents a race where we immediately switch to a new parent, who tries to do the same with us
    //	this avoids the tons of traffic generated when nodes race to use each other as parents
    pub(crate) async fn update(&self, mut info: TreeInfo, p: PeerId) {
        debug!("Dhtree update.");
        // The tree info should have been checked before this point
        info.time = SystemTime::now(); // Order by processing time, not receiving time...
        {
            let mut update_data = self.update_data.lock().unwrap();
            update_data.hseq += 1;
            info.hseq = update_data.hseq; // Used to track order without comparing timestamps, since some platforms have *horrible* time resolution

            if let Some(exp) = update_data.expired.get(&info.root) {
                if exp.seq < info.seq {
                    update_data.expired.insert(
                        info.root.clone(),
                        TreeExpiredInfo {
                            seq: info.seq,
                            time: info.time,
                        },
                    );
                }
            } else {
                update_data.expired.insert(
                    info.root.clone(),
                    TreeExpiredInfo {
                        seq: info.seq,
                        time: info.time,
                    },
                );
            }
        }

        debug!("Dhtree update.1");
        if let Some(p) = self.core().peers.get_peer(p) {
            if !self.tinfos.read().unwrap().contains_key(&p.id) {
                // The peer may have missed an update due to a race between creating the peer and now
                // The easiest way to fix the problem is to just send it another update right now
                p.send_tree(self.self_info.read().unwrap().as_ref().unwrap())
                    .unwrap();
            }

            self.tinfos.write().unwrap().insert(p.id, info.clone());

            debug!("Dhtree update.2");

            if p.id == self.parent.read().unwrap().clone() {
                if self.update_data.lock().unwrap().wait {
                    panic!("this should never happen");
                }

                let mut do_wait = false;
                if tree_less(
                    &self.self_info.read().unwrap().as_ref().unwrap().root,
                    &info.root,
                ) {
                    do_wait = true; // worse root
                } else if info.root == self.self_info.read().unwrap().as_ref().unwrap().root
                    && info.seq <= self.self_info.read().unwrap().as_ref().unwrap().seq
                {
                    do_wait = true; // same root and seq
                }

                *self.self_info.write().unwrap() = None; // The old self/parent are now invalid
                *self.parent.write().unwrap() = PeerId::nil();

                if do_wait {
                    // FIXME this is a hack
                    //  We seem to busyloop if we process parent updates immediately
                    //  E.g. we get bad news and immediately switch to a different peer
                    //  Then we get more bad news and switch again, etc...
                    // Set self to root, send, then process things correctly 1 second later
                    self.update_data.lock().unwrap().wait = true;
                    *self.self_info.write().unwrap() =
                        Some(TreeInfo::new(self.core().crypto.public_key.clone()));
                    self._send_tree(); // send bad news immediately
                    debug!("Dhtree update. send tree .2");
                    let self_clone = self.clone();

                    tokio::spawn(async move {
                        tokio::time::sleep(PEER_TIMEOUT + Duration::from_secs(1)).await;
                        self_clone.update_data.lock().unwrap().wait = false;
                        *self_clone.self_info.write().unwrap() = None;
                        *self_clone.parent.write().unwrap() = PeerId::nil();
                        self_clone._fix();
                        self_clone.do_bootstrap().await;
                    });

                    // self.wait = false;
                    // self.self_info = None;
                    // self.parent = None;
                    // self._fix().await;
                    // self._do_bootstrap().await;
                }
            }
        }
        if !self.update_data.lock().unwrap().wait {
            self._fix();
            self.do_bootstrap().await;
        }
        debug!("Dhtree update finsihed.");
    }

    // remove removes a peer from the tree, along with any paths through that peer in the dht
    pub(crate) async fn remove(&self, p: PeerId) {
        let old_info = self.tinfos.write().unwrap().remove(&p);
        if *self.self_info.read().unwrap() == old_info {
            *self.self_info.write().unwrap() = None;
            *self.parent.write().unwrap() = PeerId::nil();
            self._fix();
        }

        let dinfos: Vec<_> = { self.dinfos.read().unwrap().values().cloned().collect() };
        for dinfo in dinfos {
            if dinfo.peer == p || dinfo.rest == p {
                self.teardown(p, &dinfo.get_teardown()).await;
            }
        }
    }

    // _fix selects the best parent (and is called in response to receiving a tree update)
    // if this is not the same as our current parent, then it sends a tree update to our peers and resets our prev/next in the dht
    fn _fix(&self) {
        debug!("Dhtree fix.");
        let old_self = self.self_info.read().unwrap().clone();

        if self.self_info.read().unwrap().is_none()
            || tree_less(
                &self.core().crypto.public_key,
                &self.self_info.read().unwrap().as_ref().unwrap().root,
            )
        {
            // Note that seq needs to be non-decreasing for the node to function as a root
            //  a timestamp it used to partly mitigate rollbacks from restarting
            *self.self_info.write().unwrap() = Some(TreeInfo {
                root: self.core().crypto.public_key.clone(),
                seq: UNIX_EPOCH.elapsed().unwrap().as_secs(),
                time: SystemTime::now(),
                hseq: 0,
                hops: Vec::new(),
            });
            *self.parent.write().unwrap() = PeerId::nil();
        }
        let tinfos = &self.tinfos.read().unwrap();
        for (_, info) in tinfos.iter() {
            // Refill expired to include non-root nodes (in case we're replacing something)
            let mut update_data = self.update_data.lock().unwrap();
            if let Some(exp) = update_data.expired.get(&info.root) {
                if info.seq > exp.seq || (info.seq == exp.seq && info.time < exp.time) {
                    update_data.expired.insert(
                        info.root.clone(),
                        TreeExpiredInfo {
                            seq: info.seq,
                            time: info.time,
                        },
                    );
                }
            } else {
                // Refill expired to include non-root nodes (in case we're replacing something)
                update_data.expired.insert(
                    info.root.clone(),
                    TreeExpiredInfo {
                        seq: info.seq,
                        time: info.time,
                    },
                );
            }
        }

        for (p, info) in tinfos.iter() {
            if let Some(exp) = self.update_data.lock().unwrap().expired.get(&info.root) {
                if info.seq < exp.seq
                    || (info.seq == exp.seq && exp.time.elapsed().unwrap() > TREE_TIMEOUT)
                {
                    continue; // skip old sequence numbers
                }
            }
            if !info.check_loops() {
                debug!("fix.1");
                // This has a loop, e.g. it's from a child, so skip it
            } else if tree_less(
                &info.root,
                &self.self_info.read().unwrap().as_ref().unwrap().root,
            ) {
                debug!("fix.2");
                // This is a better root
                *self.self_info.write().unwrap() = Some(info.clone());
                *self.parent.write().unwrap() = *p;
            } else if tree_less(
                &self.self_info.read().unwrap().as_ref().unwrap().root,
                &info.root,
            ) {
                debug!("fix.3");
                // This is a worse root, so don't do anything with it
            } else if info.seq > self.self_info.read().unwrap().as_ref().unwrap().seq {
                debug!("fix.4");
                // This is a newer sequence number, so update parent
                *self.self_info.write().unwrap() = Some(info.clone());
                *self.parent.write().unwrap() = *p;
            } else if info.seq < self.self_info.read().unwrap().as_ref().unwrap().seq {
                debug!("fix.5");
                // This is an older sequence number, so ignore it
            } else if info.hseq < self.self_info.read().unwrap().as_ref().unwrap().hseq {
                debug!("fix.6");
                // This info has been around for longer (e.g. the path is more stable)
                *self.self_info.write().unwrap() = Some(info.clone());
                *self.parent.write().unwrap() = *p;
            }
        }
        debug!("fix: parent {}", self.parent.read().unwrap());

        if self.self_info.read().unwrap().as_ref() != old_self.as_ref() {
            let delay = if self.self_info.read().unwrap().as_ref().unwrap().root
                == self.core().crypto.public_key
            {
                TREE_ANNOUNCE
            } else {
                // Figure out when the root needs to time out
                let stop_time = self
                    .update_data
                    .lock()
                    .unwrap()
                    .expired
                    .get(&self.self_info.read().unwrap().as_ref().unwrap().root)
                    .unwrap()
                    .time
                    + TREE_TIMEOUT;
                stop_time.duration_since(SystemTime::now()).unwrap()
            };
            let self_info_clone = self.self_info.read().unwrap().clone();
            let self_clone = self.clone();
            tokio::spawn(async move {
                tokio::time::sleep(delay).await;

                if self_clone.self_info.read().unwrap().as_ref() == self_info_clone.as_ref() {
                    *self_clone.self_info.write().unwrap() = None;
                    *self_clone.parent.write().unwrap() = PeerId::nil();
                    self_clone._fix();
                    self_clone.do_bootstrap().await;
                }
                // if self.self_info == self_clone {
                //     self.self_info = None;
                //     self.parent = None;
                //     self.handle.do_fix().await;
                //     self._do_bootstrap().await;
                // }
            });
            self._send_tree(); // Send the tree update to our peers
        }

        // Clean up expired (remove anything worse than the current root)
        self.update_data
            .lock()
            .unwrap()
            .expired
            .retain(|v, _| !tree_less(&self.self_info.read().unwrap().as_ref().unwrap().root, v));
        debug!("Dhtree fix finished.");
    }

    // _treeLookup selects the best next hop (in treespace) for the destination
    pub(crate) fn tree_lookup(&self, dest: &TreeLabel) -> Option<Arc<Peer>> {
        debug!("++_tree_lookup. {}", dest);
        if self.core().crypto.public_key == dest.key {
            debug!("--_tree_lookup.None");
            return None;
        }

        let mut best = self.self_info.read().unwrap().as_ref().unwrap().clone();
        let mut best_dist = best.dist(dest);
        let mut best_peer: Option<Arc<Peer>> = None;
        let tinfos = self.tinfos.read().unwrap();
        for (p, info) in tinfos.iter() {
            if info.root != dest.root || info.seq != dest.seq {
                continue;
            }
            let mut tmp = info.clone();
            tmp.hops = tmp.hops[0..tmp.hops.len() - 1].to_vec();
            let dist = tmp.dist(dest);

            let mut is_better = false;
            if dist < best_dist {
                is_better = true;
            } else if dist > best_dist {
            } else if tree_less(&info.from(), &best.from()) {
                is_better = true;
            } else if let Some(peer) = &best_peer {
                if let Some(p) = self.core().peers.get_peer(*p) {
                    if peer.key == p.key
                        && p.prio.load(atomic::Ordering::SeqCst)
                            < peer.prio.load(atomic::Ordering::SeqCst)
                    {
                        // It's another link to the same next-hop node, but this link has a
                        // higher priority than the chosen one, so prefer it instead
                        is_better = true;
                    }
                }
            }

            if is_better {
                best = info.clone();
                best_dist = dist;
                best_peer = self.core().peers.get_peer(*p);
            }
        }

        if best.root != dest.root || best.seq != dest.seq {
            // Dead end, so stay here
            return None;
        }

        debug!("--_tree_lookup.Some");
        best_peer
    }

    // _dhtLookup selects the next hop needed to route closer to the destination in dht keyspace
    // this only uses the source direction of paths through the dht
    // bootstraps use slightly different logic, since they need to stop short of the destination key
    pub(crate) fn dht_lookup(
        &self,
        dest: &PublicKeyBytes,
        is_bootstrap: bool,
    ) -> Option<Arc<Peer>> {
        type State = (PublicKeyBytes, Option<PeerId>, Option<Arc<DhtInfo>>);
        fn do_update(state: &mut State, key: PublicKeyBytes, p: PeerId, d: Option<Arc<DhtInfo>>) {
            *state = (key, Some(p), d);
        }

        fn do_checked_update(
            state: &mut State,
            dest: &PublicKeyBytes,
            is_bootstrap: bool,
            key: PublicKeyBytes,
            p: PeerId,
            _d: Option<Arc<DhtInfo>>,
        ) {
            let best = &state.0;
            if (!is_bootstrap && key == *dest && best != dest) || dht_ordered(best, &key, dest) {
                *state = (key, Some(p), None);
            }
        }
        fn do_ancestry(
            state: &mut State,
            dhtree: &Dhtree,
            dest: &PublicKeyBytes,
            is_bootstrap: bool,
            info: &TreeInfo,
            p: PeerId,
        ) {
            do_checked_update(state, dest, is_bootstrap, info.root.clone(), p, None);
            for hop in &info.hops {
                do_checked_update(state, dest, is_bootstrap, hop.next.clone(), p, None);
                let best_peer = state.1.as_ref();
                if let Some(best_peer) = best_peer {
                    if let Some(tinfo) = dhtree.tinfos.read().unwrap().get(best_peer) {
                        if state.0 == hop.next && info.hseq < tinfo.hseq {
                            do_update(state, hop.next.clone(), p, None);
                        }
                    }
                }
            }
        }

        fn do_dht(
            state: &mut State,
            dest: &PublicKeyBytes,
            is_bootstrap: bool,
            info: &Arc<DhtInfo>,
        ) {
            do_checked_update(
                state,
                dest,
                is_bootstrap,
                info.key.clone(),
                info.peer,
                Some(info.clone()),
            );
            let best_info = state.2.clone();
            if let Some(best_info) = best_info {
                if info.key == best_info.key
                    && (tree_less(&info.root, &best_info.root)
                        || (info.root == best_info.root && info.root_seq > best_info.root_seq))
                {
                    do_update(state, info.key.clone(), info.peer, Some(info.clone()));
                }
            }
        }

        // Start by defining variables and helper functions
        let mut state = (self.core().crypto.public_key.clone(), None, None);

        debug!("lookup.1 {}", dest);
        if (is_bootstrap && state.0/*best*/ == *dest)
            || dht_ordered(
                &self.self_info.read().unwrap().as_ref().unwrap().root,
                dest,
                &state.0,
            )
        {
            do_update(
                &mut state,
                self.self_info
                    .read()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .root
                    .clone(),
                *self.parent.read().unwrap(),
                None,
            );
        }
        debug!("lookup.2: {}", self.parent.read().unwrap());

        do_ancestry(
            &mut state,
            self,
            dest,
            is_bootstrap,
            self.self_info.read().unwrap().as_ref().unwrap(),
            *self.parent.read().unwrap(),
        );

        debug!("lookup.3");
        for (p, info) in self.tinfos.read().unwrap().iter() {
            do_ancestry(&mut state, self, dest, is_bootstrap, info, *p);
        }

        debug!("lookup.4");
        self.tinfos.read().unwrap().iter().for_each(|(p, _)| {
            debug!("_dht_lookup {:?}", p);
            if let Some(peer) = &self.core().peers.get_peer(*p) {
                if state.0/*best*/ == peer.key {
                    do_update(&mut state, peer.key.clone(), *p, None);
                }
            }
        });

        debug!("lookup.5");
        self.dinfos.read().unwrap().iter().for_each(|(_, info)| {
            debug!("_dht_lookup {:?}", info);
            do_dht(&mut state, dest, is_bootstrap, info);
        });

        debug!("lookup.6");

        let best_peer = state.1.filter(|&pid| pid != PeerId::nil());
        let best_peer = if let Some(pid) = best_peer {
            self.core().peers.get_peer(pid)
        } else {
            None
        };

        debug!("lookup.7");
        if let Some(best_peer) = best_peer.as_ref() {
            let tinfos = self.tinfos.read().unwrap();
            for (p, _) in tinfos.iter() {
                debug!("lookup.7.0");
                if let Some(p) = self.core().peers.get_peer(*p) {
                    debug!("lookup.7.1");
                    if p.key == best_peer.key
                        && p.prio.load(atomic::Ordering::Relaxed)
                            < best_peer.prio.load(atomic::Ordering::Relaxed)
                    {
                        debug!("lookup.7.2");
                        do_update(&mut state, p.key.clone(), p.id, None);
                    }
                    debug!("lookup.7.3");
                }
            }
            debug!("lookup.7.4");
            debug!("_dht_lookup {}", best_peer.id);
        } else {
            debug!("_dht_lookup None");
        }

        best_peer
    }

    // _dhtAdd adds a dhtInfo to the dht and returns true
    // it may return false if the path associated with the dhtInfo isn't allowed for some reason
    // e.g. we know a better prev/next for one of the nodes in the path, which can happen if there's multiple split rings that haven't converged on their own yet
    // as of writing, that never happens, it always adds and returns true
    fn dht_add(&self, info: Arc<DhtInfo>) -> bool {
        // TODO? check existing paths, don't allow this one if the source/dest pair makes no sense
        self.dinfos
            .write()
            .unwrap()
            .insert(info.get_map_key(), info);
        true
    }

    // _newBootstrap returns a *dhtBootstrap for this node, using t.self, with a signature
    fn _new_bootstrap(&self) -> DhtBootstrap {
        DhtBootstrap {
            label: self.get_label(),
        }
    }

    // _handleBootstrap takes a bootstrap packet and checks if we know of a better prev for the source node
    // if yes, then we forward to the next hop in the path towards that prev
    // if no, then we reply with a dhtBootstrapAck (unless sanity checks fail)
    pub(super) async fn handle_bootstrap(&self, bootstrap: &DhtBootstrap) {
        debug!("Dhtree _handle_bootstrap.");
        debug!("Dhtree {:?}", bootstrap);
        let source = bootstrap.label.key.clone();
        let next = self
            .dht_lookup(&source, true)
            .map_or(PeerId::nil(), |v| v.id);
        debug!("Dhtree _handle_bootstrap.1");
        if next != PeerId::nil() {
            debug!("Dhtree _handle_bootstrap.1.1");
            debug!("send to peer.");
            if let Some(p) = self.core().peers.get_peer(next) {
                p.send_bootstrap(bootstrap).unwrap()
            }
            debug!("Dhtree _handle_bootstrap.end");
            return;
        } else if source == self.core().crypto.public_key {
            debug!("Dhtree _handle_bootstrap.1.2");
            debug!("Dhtree _handle_bootstrap.end");
            return;
        } else if !bootstrap.check() {
            debug!("Dhtree _handle_bootstrap.1.3");
            debug!("Dhtree _handle_bootstrap.end");
            return;
        }
        let ack = DhtBootstrapAck {
            bootstrap: bootstrap.clone(),
            response: self.get_token(source),
        };
        self.handle_bootstrap_ack(&ack).await;
        debug!("Dhtree _handle_bootstrap.end");
    }

    // _handleBootstrapAck takes an ack packet and checks if we know a next hop on the tree
    // if yes, then we forward to the next hop
    // if no, then we decide whether or not this node is better than our current prev
    // if yes, then we get rid of our current prev (if any) and start setting up a new path to the response node in the ack
    // if no, then we drop the bootstrap acknowledgement without doing anything
    pub(super) async fn handle_bootstrap_ack(&self, ack: &DhtBootstrapAck) -> Result<(), String> {
        debug!("Dhtree _handle_bootstrap_ack.");
        let source = ack.response.dest.key.clone();
        if let Some(next) = self.tree_lookup(&ack.bootstrap.label) {
            debug!("Dhtree _handle_bootstrap_ack.1");
            next.send_bootstrap_ack(ack).map_err(|e| e.to_string())?;
            debug!("Dhtree _handle_bootstrap_ack.1.end");
            return Ok(());
        }

        if self.core().crypto.public_key == source
            || self.core().crypto.public_key != ack.bootstrap.label.key
            || self.core().crypto.public_key != ack.response.source
            || self.self_info.read().unwrap().as_ref().unwrap().root != ack.response.dest.root
            || self.self_info.read().unwrap().as_ref().unwrap().seq != ack.response.dest.seq
        {
            debug!("Dhtree _handle_bootstrap_ack.2.end");
            return Ok(());
        } else if self.prev.read().unwrap().as_ref().is_none()
            || dht_ordered(
                self.dkeys
                    .read()
                    .unwrap()
                    .get(self.prev.read().unwrap().as_ref().unwrap())
                    .unwrap(),
                &source,
                &self.core().crypto.public_key,
            )
        {
        } else if &source
            != self
                .dkeys
                .read()
                .unwrap()
                .get(self.prev.read().unwrap().as_ref().unwrap())
                .unwrap()
        {
            debug!("Dhtree _handle_bootstrap_ack.3.end");
            return Ok(());
        } else if self.prev.read().unwrap().as_ref().unwrap().root
            != self.self_info.read().unwrap().as_ref().unwrap().root
            || self.prev.read().unwrap().as_ref().unwrap().root_seq
                != self.self_info.read().unwrap().as_ref().unwrap().seq
        {
        } else {
            debug!("Dhtree _handle_bootstrap_ack.4.end");
            return Ok(());
        }

        if !ack.response.check() {
            // Final thing to check, if the signatures are bad then ignore it
            return Ok(());
        }

        *self.prev.write().unwrap() = None;
        let dinfo_keys: Vec<_> = self.dinfos.read().unwrap().keys().cloned().collect();
        for key in dinfo_keys {
            // Former prev need to be notified that we're no longer next
            // The only way to signal that is by tearing down the path
            // We may have multiple former prev paths
            //  From t.prev = nil when the tree changes, but kept around to bootstrap
            // So loop over paths and close any going to a *different* node than the current prev
            // The current prev can close the old path from that side after setup
            let dinfo = &self.dinfos.read().unwrap()[&key].clone();
            if let Some(dest) = {
                let dest = self.dkeys.read().unwrap().get(dinfo).cloned();
                dest
            } {
                if dest != source {
                    self.teardown(PeerId::nil(), &dinfo.get_teardown()).await;
                }
            }
        }

        let setup = self._new_setup(&ack.response);
        self.handle_setup(PeerId::nil(), &setup).await;
        debug!("Dhtree _handle_bootstrap_ack.end");
        Ok(())
    }

    fn _new_setup(&self, token: &DhtSetupToken) -> DhtSetup {
        let seq = self.seq.fetch_add(1, atomic::Ordering::Relaxed);
        let mut setup = DhtSetup {
            sig: Default::default(),
            seq: seq + 1,
            token: token.clone(),
        };

        setup.sig = self.core().crypto.private_key.sign(&setup.bytes_for_sig());
        setup
    }

    // _handleSetup checks if it's safe to add a path from the setup source to the setup destination
    // if we can't add it (due to no next hop to forward it to, or if we're the destination but we already have a better next, or if we already have a path from the same source node), then we send a teardown to remove the path from the network
    // otherwise, we add the path to our table, and forward it (if we're not the destination) or set it as our next path (if we are, tearing down our existing next if one exists)
    pub(super) async fn handle_setup(&self, prev: PeerId, setup: &DhtSetup) {
        debug!("++_handle_setup");
        let next = self.tree_lookup(&setup.token.dest);
        let dest = setup.token.dest.key.clone();
        if next.is_none() && !dest.eq(&self.core().crypto.public_key) {
            // FIXME? this has problems if prev is self (from changes to tree state?)
            if prev != PeerId::nil() {
                if let Some(p) = self.core().peers.get_peer(prev) {
                    p.send_teardown(&setup.get_teardown()).unwrap()
                }
            }
            debug!("--_handle_setup.1");
            return;
        }
        debug!("  _handle_setup.1");
        let dinfo = DhtInfo {
            seq: setup.seq,
            key: setup.token.source.clone(),
            peer: prev,
            rest: next.as_ref().map_or(PeerId::nil(), |p| p.id),
            root: setup.token.dest.root.clone(),
            root_seq: setup.token.dest.seq,
            timer: Instant::now(),
        };
        if !dinfo
            .root
            .eq(&self.self_info.read().unwrap().as_ref().unwrap().root)
            || dinfo.root_seq != self.self_info.read().unwrap().as_ref().unwrap().seq
        {
            // Wrong root or mismatched seq
            if prev != PeerId::nil() {
                if let Some(p) = self.core().peers.get_peer(prev) {
                    p.send_teardown(&setup.get_teardown()).unwrap()
                }
            }
            debug!("--_handle_setup.2");
            return;
        }
        debug!("  _handle_setup.2");
        if self
            .dinfos
            .read()
            .unwrap()
            .contains_key(&dinfo.get_map_key())
        {
            // Already have a path from this source
            if prev != PeerId::nil() {
                if let Some(p) = self.core().peers.get_peer(prev) {
                    p.send_teardown(&setup.get_teardown()).unwrap()
                }
            }
            debug!("--_handle_setup.3");
            return;
        }
        debug!("  _handle_setup.3");
        let dinfo = Arc::new(dinfo);
        if !self.dht_add(dinfo.clone()) && prev != PeerId::nil() {
            if let Some(p) = self.core().peers.get_peer(prev) {
                p.send_teardown(&setup.get_teardown()).unwrap()
            }
        }
        let dinfo_key = dinfo.get_map_key();

        debug!("  _handle_setup.4");
        let self_clone = self.clone();
        tokio::spawn(async move {
            tokio::time::sleep(2 * TREE_TIMEOUT).await;
            if let Some(info) = {
                let info = self_clone.dinfos.read().unwrap().get(&dinfo_key).cloned();
                info
            } {
                if let Some(p) = self_clone.core().peers.get_peer(info.peer) {
                    p.send_teardown(&info.get_teardown()).unwrap()
                }
                self_clone.teardown(info.peer, &info.get_teardown()).await;
            }
        });

        if prev == PeerId::nil() {
            if !setup.token.source.eq(&self.core().crypto.public_key) {
                panic!("wrong source");
            } else if setup.seq != self.seq.load(atomic::Ordering::Relaxed) {
                panic!("wrong seq");
            } else if self.prev.read().unwrap().is_some() {
                panic!("already have a prev");
            }
            *self.prev.write().unwrap() = Some(dinfo.clone());
            self.dkeys.write().unwrap().insert(dinfo.clone(), dest);
        }
        if let Some(next) = next {
            next.send_setup(setup).await.unwrap();
        } else if self.next.read().unwrap().is_some() {
            // TODO get this right!
            //  We need to replace the old next in most cases
            //  The exceptions are when:
            //    1. The dinfo's root/seq don't match our current root/seq
            //    2. The dinfo matches, but so does t.next, and t.next is better
            //  What happens when the dinfo matches, t.next does not, but t.next is still better?...
            //  Just doing something for now (replace next) but not sure that's right...
            let do_update = {
                if !dinfo
                    .root
                    .eq(&self.self_info.read().unwrap().as_ref().unwrap().root)
                    || dinfo.root_seq != self.self_info.read().unwrap().as_ref().unwrap().seq
                {
                    // The root/seq is bad, so don't update
                    false
                } else if dinfo
                    .key
                    .eq(&self.next.read().unwrap().as_ref().unwrap().key)
                {
                    // It's an update from the current next
                    true
                } else if dht_ordered(
                    &self.core().crypto.public_key,
                    &dinfo.key,
                    &self.next.read().unwrap().as_ref().unwrap().key,
                ) {
                    // It's an update from a better next
                    true
                } else {
                    false
                }
            };
            if do_update {
                let teardown = self.next.read().unwrap().as_ref().unwrap().get_teardown();
                self.teardown(PeerId::nil(), &teardown).await;
                *self.next.write().unwrap() = Some(dinfo);
            } else {
                self.teardown(PeerId::nil(), &dinfo.get_teardown()).await;
            }
        } else {
            *self.next.write().unwrap() = Some(dinfo);
        }
        debug!("--_handle_setup");
    }

    pub(super) async fn teardown(&self, from: PeerId, teardown: &DhtTeardown) {
        let key = teardown.get_map_key();
        if let Some(dinfo) = {
            let dinfo = self.dinfos.read().unwrap().get(&key).cloned();
            dinfo
        } {
            if teardown.seq != dinfo.seq {
                return;
            } else if teardown.key != dinfo.key {
                panic!("this should never happen");
            }
            let next = if from == dinfo.peer {
                dinfo.rest
            } else if from == dinfo.rest {
                dinfo.peer
            } else {
                return; // panic("DEBUG teardown of path from wrong node")
            };

            self.dkeys.write().unwrap().remove(&dinfo);
            self.dinfos.write().unwrap().remove(&key);

            if !next.is_nil() {
                if let Some(next) = self.core().peers.get_peer(next) {
                    next.send_teardown(teardown).unwrap()
                }
            }
            if let Some(next) = self.next.read().unwrap().as_ref() {
                if next == &dinfo {
                    *self.next.write().unwrap() = None;
                }
            }
            if let Some(prev) = {
                let prev = self.prev.read().unwrap().clone();
                prev
            } {
                if prev == dinfo {
                    *self.prev.write().unwrap() = None;
                    // It's possible that other bad news is incoming
                    // Delay bootstrap until we've processed any other queued messages
                    // TODO: Implement `act` method
                    self.do_bootstrap().await;
                }
            }
        }
    }

    // _doBootstrap decides whether or not to send a bootstrap packet
    // if a bootstrap is sent, then it sets things up to attempt to send another bootstrap at a later point
    fn do_bootstrap(&self) -> BoxFuture<'_, ()> {
        debug!("Dhtree do_bootstrap.");
        let self_clone = self.clone();
        async move {
            if !self_clone.bwait.load(atomic::Ordering::Relaxed)
                && self_clone.btimer.load(atomic::Ordering::Relaxed)
            {
                if let Some(prev) = self_clone.prev.read().unwrap().as_ref() {
                    if prev.root == self_clone.self_info.read().unwrap().as_ref().unwrap().root
                        && prev.root_seq
                            == self_clone.self_info.read().unwrap().as_ref().unwrap().seq
                    {
                        debug!("Dhtree do_bootstrap. finished");
                        return;
                    }
                }
                if self_clone.self_info.read().unwrap().as_ref().unwrap().root
                    != self_clone.core().crypto.public_key
                {
                    self_clone
                        .handle_bootstrap(&self_clone._new_bootstrap())
                        .await;
                    // Don't immediately send more bootstraps if called again too quickly
                    // This helps prevent traffic spikes in some mobility scenarios
                    self_clone.bwait.store(true, atomic::Ordering::Relaxed);
                }
                self_clone.btimer.store(false, atomic::Ordering::Relaxed);
                //let handle = self.handle();
                let self_clone_clone = self_clone.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    self_clone_clone
                        .bwait
                        .store(false, atomic::Ordering::Relaxed);
                    self_clone_clone
                        .btimer
                        .store(false, atomic::Ordering::Relaxed);
                    self_clone_clone.do_bootstrap().await;
                });
                self_clone.btimer.store(true, atomic::Ordering::Relaxed);
                // self.bwait = false;
                // self._do_bootstrap().await;
                debug!("Dhtree do_bootstrap. finished");
            } else {
                debug!("Dhtree do_bootstrap. finished");
            }
        }
        .boxed()
    }

    // handleDHTTraffic take a dht traffic packet (still marshaled as []bytes) and decides where to forward it to next to take it closer to its destination in keyspace
    // if there's nowhere better to send it, then it hands it off to be read out from the local PacketConn interface
    pub(super) async fn handle_dht_traffic(&self, tr: DhtTraffic, do_notify: bool) {
        debug!("++handle_dht_traffic");
        let next = self.dht_lookup(&tr.dest, false);
        debug!("Dhtree handle_dht_traffic.1");
        if next.is_none() {
            if tr.dest.eq(&self.core().crypto.public_key) {
                let dest = tr.source.clone();
                let pathfinder = self.pathfinder.clone();
                debug!("Dhtree handle_dht_traffic.1.2");
                //tokio::spawn(async move {
                pathfinder.do_notify(&dest, !do_notify).await;
                //});
            }
            debug!("Dhtree handle_dht_traffic.1.3");
            let pconn = self.core().pconn.clone();
            //tokio::spawn(async move {
            pconn.handle_traffic(tr).await;
        //    });
        } else if let Some(next) = next {
            debug!("Dhtree handle_dht_traffic.2");
            next.send_dht_traffic(tr).unwrap();
        }
        debug!("--handle_dht_traffic");
    }

    pub async fn send_traffic(&self, tr: DhtTraffic) {
        debug!("++send_traffic");
        if let Some(path) = self.pathfinder.get_path(&tr.dest).await {
            debug!("Path: {:?}", path);
            if !path.is_empty() {
                let pt = PathTraffic {
                    path,
                    dt: tr.clone(),
                };
                if let Err(e) = self.core().peers.handle_path_traffic(pt).await {
                    error!("  handle_path_traffic error: {:?}", e);
                }
            } else {
                self.handle_dht_traffic(tr, false).await;
            }
        } else {
            self.handle_dht_traffic(tr, false).await;
        }
        debug!("--send_traffic");
    }

    pub fn get_label(&self) -> TreeLabel {
        // Fill easy fields of label
        let mut label = TreeLabel {
            key: self.core().crypto.public_key.clone(),
            root: self
                .self_info
                .read()
                .unwrap()
                .as_ref()
                .unwrap()
                .root
                .clone(),
            seq: self.self_info.read().unwrap().as_ref().unwrap().seq,
            path: self
                .self_info
                .read()
                .unwrap()
                .as_ref()
                .unwrap()
                .hops
                .iter()
                .map(|hop| hop.port)
                .collect(),
            sig: SignatureBytes::default(), // temporary value, will be replaced
        };

        let bs = label.bytes_for_sig();
        label.sig = self.core().crypto.private_key.sign(&bs);
        label
    }

    pub fn get_token(&self, source: PublicKeyBytes) -> DhtSetupToken {
        let mut token = DhtSetupToken {
            source,
            dest: self.get_label(),
            sig: SignatureBytes::default(), // temporary value, will be replaced
        };

        let bs = token.bytes_for_sig();
        token.sig = self.core().crypto.private_key.sign(&bs);
        token
    }
}

#[derive(Debug, Clone)]
pub struct DhtTraffic {
    pub source: PublicKeyBytes,
    pub dest: PublicKeyBytes,
    pub kind: u8, // in-band vs out-of-band, TODO? separate type?
    pub payload: Vec<u8>,
}

impl fmt::Display for DhtTraffic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DhtTraffic {{ source: {}, dest: {}, kind: {}, payload: len({}) ... }}",
            self.source,
            self.dest,
            self.kind,
            self.payload.len() //            hex::encode(&self.payload)
        )
    }
}

impl Encode for DhtTraffic {
    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.source.as_bytes());
        out.extend_from_slice(self.dest.as_bytes());
        out.push(self.kind);
        out.extend_from_slice(&self.payload);
    }
}

impl Decode for DhtTraffic {
    fn decode(data: &[u8]) -> Result<Self, WireDecodeError> {
        let mut cursor = Cursor::new(data);

        let mut source = [0u8; PUBLIC_KEY_SIZE];
        let mut dest = [0u8; PUBLIC_KEY_SIZE];
        cursor
            .read_exact(&mut source)
            .map_err(|_| WireDecodeError)?;
        cursor.read_exact(&mut dest).map_err(|_| WireDecodeError)?;

        let kind = cursor.read_u8().map_err(|_| WireDecodeError)?;

        let mut payload = Vec::new();
        cursor
            .read_to_end(&mut payload)
            .map_err(|_| WireDecodeError)?;

        Ok(Self {
            source: PublicKeyBytes(source),
            dest: PublicKeyBytes(dest),
            kind,
            payload,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct TreeInfo {
    pub time: SystemTime, // This field is not serialized
    pub hseq: u64,
    pub root: PublicKeyBytes,
    pub seq: u64,
    pub hops: Vec<TreeHop>,
}

impl fmt::Display for TreeInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Time: {:?} s, hseq: {}, root: {}, seq: {}, hops: ",
            self.time, self.hseq, self.root, self.seq
        )?;
        for (i, hop) in self.hops.iter().enumerate() {
            if i != 0 {
                write!(f, ", ")?;
            }
            write!(f, "{}", hop)?;
        }
        Ok(())
    }
}

impl Encode for TreeInfo {
    fn encode(&self, out: &mut Vec<u8>) {
        // Encode root
        out.extend_from_slice(self.root.0.as_ref());

        // Encode seq
        out.extend_from_slice(&self.seq.to_be_bytes());

        // Encode hops
        for hop in &self.hops {
            out.extend_from_slice(hop.next.0.as_ref()); // Encode next PublicKeyBytes
            out.extend_from_slice(&hop.port.encode_var_vec()); // Encode port as varint
            out.extend_from_slice(hop.sig.0.as_ref()); // Encode sig SignatureBytes
        }
    }
}
impl Decode for TreeInfo {
    fn decode(data: &[u8]) -> Result<Self, WireDecodeError> {
        let mut cursor = Cursor::new(data);

        let time = SystemTime::now(); // This field is not deserialized, use current time
        let mut root = [0u8; PUBLIC_KEY_SIZE];
        cursor.read_exact(&mut root).map_err(|_| WireDecodeError)?;
        let seq = cursor
            .read_u64::<BigEndian>()
            .map_err(|_| WireDecodeError)?;
        let mut hops = Vec::new();
        while (cursor.position() as usize) < data.len() {
            let mut next = [0u8; PUBLIC_KEY_SIZE];
            cursor.read_exact(&mut next).map_err(|_| WireDecodeError)?;

            let port = cursor.read_varint::<u64>().map_err(|_| WireDecodeError)? as PeerPort;

            let mut sig = [0u8; SIGNATURE_SIZE];
            cursor.read_exact(&mut sig).map_err(|_| WireDecodeError)?;

            hops.push(TreeHop {
                next: PublicKeyBytes(next),
                port,
                sig: SignatureBytes(sig),
            });
        }

        Ok(Self {
            time,
            hseq: 0,
            root: PublicKeyBytes(root),
            seq,
            hops,
        })
    }
}

impl TreeInfo {
    pub fn new(root: PublicKeyBytes) -> Self {
        TreeInfo {
            time: SystemTime::now(),
            hseq: 0,
            root,
            seq: 0,
            hops: Vec::new(),
        }
    }

    pub fn dest(&self) -> PublicKeyBytes {
        if !self.hops.is_empty() {
            self.hops.last().unwrap().next.clone()
        } else {
            self.root.clone()
        }
    }

    pub fn from(&self) -> PublicKeyBytes {
        if self.hops.len() > 1 {
            self.hops[self.hops.len() - 2].next.clone()
        } else {
            self.root.clone()
        }
    }

    pub fn check_sigs(&self) -> bool {
        if self.hops.is_empty() {
            return false;
        }

        let mut bs = Vec::new();
        let mut key = self.root.clone();

        /*Replace with your actual implementation*/
        bs.extend_from_slice(self.root.as_bytes());

        let seq = self.seq.to_be_bytes();
        bs.extend_from_slice(&seq);

        for hop in &self.hops {
            /*Replace with your actual implementation*/
            bs.extend_from_slice(hop.next.as_bytes());

            // Assuming wireEncodeUint is a function to encode the port value to bytes
            bs.extend_from_slice(&hop.port.encode_var_vec());

            if !key.verify(&bs, hop.sig.as_bytes()) {
                return false;
            }
            key = hop.next.clone();
        }
        true
    }

    pub fn check_loops(&self) -> bool {
        let mut key = self.root.clone();
        let mut keys = HashSet::new();

        for hop in &self.hops {
            if keys.contains(&key) {
                return false;
            }
            keys.insert(key);
            key = hop.next.clone();
        }
        !keys.contains(&key)
    }

    pub fn add(&self, priv_key: PrivateKeyBytes, next: &Peer) -> TreeInfo {
        let mut bs = Vec::new();
        bs.extend_from_slice(self.root.as_bytes());

        let seq = self.seq.to_be_bytes();
        bs.extend_from_slice(&seq);

        for hop in &self.hops {
            bs.extend_from_slice(hop.next.as_bytes());
            bs.extend_from_slice(&hop.port.encode_var_vec());
        }

        bs.extend_from_slice(next.key.as_bytes());
        bs.extend_from_slice(&next.port.encode_var_vec());

        let sig = priv_key.sign(&bs);

        let hop = TreeHop {
            next: next.key.clone(),
            port: next.port,
            sig,
        };

        let mut new_info = self.clone();
        new_info.hops.push(hop);
        new_info
    }

    pub fn dist(&self, dest: &TreeLabel) -> usize {
        if self.root != dest.root {
            return usize::MAX / 2; // half of max usize value
        }

        let (a, b) = if self.hops.len() < dest.path.len() {
            (self.hops.len(), dest.path.len())
        } else {
            (dest.path.len(), self.hops.len())
        };

        let mut lca_idx = -1; // last common ancestor
        for idx in 0..a {
            if self.hops[idx].port != dest.path[idx] {
                // cast to u8 if port is not u8
                break;
            }
            lca_idx = idx as isize;
        }
        a + b - 2 * ((lca_idx + 1) as usize)
    }
}
#[derive(Debug, Clone, PartialEq)]
pub struct TreeHop {
    pub next: PublicKeyBytes,
    pub port: PeerPort,
    pub sig: SignatureBytes,
}

impl fmt::Display for TreeHop {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Next: {}, Port: {}, Signature: {}",
            self.next,
            self.port,
            hex::encode(self.sig.0)
        )
    }
}

#[derive(Debug, Clone)]
pub struct DhtBootstrap {
    label: TreeLabel,
}

impl DhtBootstrap {
    fn check(&self) -> bool {
        self.label.check()
    }
}
impl fmt::Display for DhtBootstrap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Label: {}", self.label)
    }
}

impl Encode for DhtBootstrap {
    fn encode(&self, out: &mut Vec<u8>) {
        // Encode label
        self.label.encode(out);
    }
}

impl Decode for DhtBootstrap {
    fn decode(data: &[u8]) -> Result<Self, WireDecodeError> {
        let label = TreeLabel::decode(data)?;

        Ok(Self { label })
    }
}

#[derive(Debug)]
pub struct DhtBootstrapAck {
    bootstrap: DhtBootstrap,
    response: DhtSetupToken,
}

impl fmt::Display for DhtBootstrapAck {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Bootstrap: {}, Response: {}",
            self.bootstrap, self.response
        )
    }
}

impl Encode for DhtBootstrapAck {
    fn encode(&self, out: &mut Vec<u8>) {
        // Encode bootstrap
        let mut bootstrap_bytes = vec![];
        self.bootstrap.encode(&mut bootstrap_bytes);

        // Write the length of the bootstrap_bytes as varint
        let bootstrap_len = bootstrap_bytes.len() as u64;
        out.extend_from_slice(&bootstrap_len.encode_var_vec());

        // Write the bootstrap_bytes
        out.extend(bootstrap_bytes);

        // Encode response
        self.response.encode(out);
    }
}

impl Decode for DhtBootstrapAck {
    fn decode(data: &[u8]) -> Result<Self, WireDecodeError> {
        let mut cursor = Cursor::new(data);
        let boot_bytes: u64 = cursor.read_varint().map_err(|_| WireDecodeError)?;
        let pos = cursor.position();
        let bootstrap = DhtBootstrap::decode(&data[pos as usize..(pos + boot_bytes) as usize])?;
        let response = DhtSetupToken::decode(&data[(pos + boot_bytes) as usize..])?;

        Ok(Self {
            bootstrap,
            response,
        })
    }
}

#[derive(Debug)]
pub struct DhtSetup {
    sig: SignatureBytes,
    seq: u64,
    token: DhtSetupToken,
}

impl fmt::Display for DhtSetup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DhtSetup {{ sig: {}, seq: {}, token: {} }}",
            self.sig, self.seq, self.token
        )
    }
}

impl Encode for DhtSetup {
    fn encode(&self, out: &mut Vec<u8>) {
        // Encode sig
        out.extend_from_slice(self.sig.as_bytes());

        // Encode seq
        out.extend_from_slice(&self.seq.to_be_bytes());

        // Encode token
        self.token.encode(out);
    }
}

impl Decode for DhtSetup {
    fn decode(data: &[u8]) -> Result<Self, WireDecodeError> {
        let mut cursor = Cursor::new(data);

        let mut sig = [0u8; SIGNATURE_SIZE];
        cursor.read_exact(&mut sig).map_err(|_| WireDecodeError)?;

        let seq = cursor
            .read_u64::<BigEndian>()
            .map_err(|_| WireDecodeError)?;

        // Remaining bytes should be DhtSetupToken
        let token = DhtSetupToken::decode(&data[cursor.position() as usize..])?;

        Ok(Self {
            sig: SignatureBytes(sig),
            seq,
            token,
        })
    }
}

impl DhtSetup {
    pub fn bytes_for_sig(&self) -> Vec<u8> {
        let mut bs = self.seq.to_be_bytes().to_vec();
        self.token.encode(&mut bs);
        bs
    }

    pub fn check(&self) -> bool {
        if !self.token.check() {
            return false;
        }
        let bs = self.bytes_for_sig();
        let res = self.token.source.verify(&bs, self.sig.as_bytes());
        if !res {
            panic!("DhtSetup verify failed.")
        }
        true
    }

    pub fn get_teardown(&self) -> DhtTeardown {
        DhtTeardown {
            seq: self.seq,
            key: self.token.source.clone(),
            root: self.token.dest.root.clone(),
            root_seq: self.token.dest.seq,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DhtSetupToken {
    sig: SignatureBytes,
    source: PublicKeyBytes,
    dest: TreeLabel,
}

impl fmt::Display for DhtSetupToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Signature: {}, Source: {}, Dest: {}",
            self.sig, self.source, self.dest
        )
    }
}

impl DhtSetupToken {
    pub fn bytes_for_sig(&self) -> Vec<u8> {
        let mut bs = self.source.0.to_vec();
        self.dest.encode(&mut bs);
        bs
    }

    pub fn check(&self) -> bool {
        let bs = self.bytes_for_sig();
        let res = self.dest.key.verify(&bs, self.sig.as_bytes()) && self.dest.check();
        if !res {
            debug!("DhtSetupToken verify failed");
        }
        true
    }
}

impl Encode for DhtSetupToken {
    fn encode(&self, out: &mut Vec<u8>) {
        // Encode sig
        out.extend_from_slice(self.sig.as_bytes());

        // Encode source
        out.extend_from_slice(self.source.as_bytes());

        // Encode dest
        self.dest.encode(out);
    }
}

impl Decode for DhtSetupToken {
    fn decode(data: &[u8]) -> Result<Self, WireDecodeError> {
        let mut cursor = Cursor::new(data);

        let mut sig = [0u8; SIGNATURE_SIZE];
        cursor.read_exact(&mut sig).map_err(|_| WireDecodeError)?;

        let mut source = [0u8; PUBLIC_KEY_SIZE];
        cursor
            .read_exact(&mut source)
            .map_err(|_| WireDecodeError)?;

        // Decode the remaining bytes as a TreeLabel
        let dest_data = &data[cursor.position() as usize..];
        let dest = TreeLabel::decode(dest_data)?;

        Ok(Self {
            sig: SignatureBytes(sig),
            source: PublicKeyBytes(source),
            dest,
        })
    }
}

#[derive(Clone, Debug)]
pub struct TreeLabel {
    sig: SignatureBytes,
    pub key: PublicKeyBytes,
    root: PublicKeyBytes,
    seq: u64,
    path: Vec<PeerPort>,
}

impl TreeLabel {
    pub fn bytes_for_sig(&self) -> Vec<u8> {
        let mut bs = self.root.0.to_vec();
        bs.extend_from_slice(&self.seq.to_be_bytes());
        encode_path(&self.path, &mut bs);
        bs
    }

    pub fn check(&self) -> bool {
        let bs = self.bytes_for_sig();
        if !self.key.verify(&bs, self.sig.as_bytes()) {
            panic!("TreeLabel verify failed.");
        }
        true
    }
}

impl Encode for TreeLabel {
    fn encode(&self, out: &mut Vec<u8>) {
        // Encode sig
        out.extend_from_slice(self.sig.as_bytes());

        // Encode key
        out.extend_from_slice(self.key.as_bytes());

        // Encode root
        out.extend_from_slice(self.root.as_bytes());

        // Encode seq
        out.extend_from_slice(&self.seq.to_be_bytes());

        // Encode path
        encode_path(&self.path, out);
    }
}

impl Decode for TreeLabel {
    fn decode(data: &[u8]) -> Result<Self, WireDecodeError> {
        let mut cursor = Cursor::new(data);

        let mut sig = [0u8; SIGNATURE_SIZE];
        cursor.read_exact(&mut sig).map_err(|_| WireDecodeError)?;

        let mut key = [0u8; PUBLIC_KEY_SIZE];
        cursor.read_exact(&mut key).map_err(|_| WireDecodeError)?;

        let mut root = [0u8; PUBLIC_KEY_SIZE];
        cursor.read_exact(&mut root).map_err(|_| WireDecodeError)?;

        let seq = cursor
            .read_u64::<BigEndian>()
            .map_err(|_| WireDecodeError)?;

        let mut path = Vec::new();
        while cursor.position() < data.len() as u64 {
            let peer_port = cursor.read_varint().map_err(|_| WireDecodeError)?;
            path.push(peer_port);
            if peer_port == 0 {
                break;
            }
        }

        Ok(Self {
            sig: SignatureBytes(sig),
            key: PublicKeyBytes(key),
            root: PublicKeyBytes(root),
            seq,
            path,
        })
    }
}

impl fmt::Display for TreeLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Signature: {}, Key: {}, Root: {}, Seq: {}, Path: [",
            self.sig, self.key, self.root, self.seq
        )?;
        for (index, port) in self.path.iter().enumerate() {
            if index != 0 {
                write!(f, ", ")?;
            }
            write!(f, "{}", port)?;
        }
        write!(f, "]")
    }
}

#[derive(Debug)]
pub struct DhtTeardown {
    seq: u64,
    key: PublicKeyBytes,
    root: PublicKeyBytes,
    root_seq: u64,
}

impl DhtTeardown {
    pub fn get_map_key(&self) -> DhtMapKey {
        DhtMapKey {
            key: self.key.clone(),
            root: self.root.clone(),
            root_seq: self.root_seq,
        }
    }
}

impl fmt::Display for DhtTeardown {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DhtTeardown {{ seq: {}, key: {}, root: {}, root_seq: {} }}",
            self.seq, self.key, self.root, self.root_seq
        )
    }
}

impl Encode for DhtTeardown {
    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.seq.to_be_bytes());
        out.extend_from_slice(&self.key.0);
        out.extend_from_slice(&self.root.0);
        out.extend_from_slice(&self.root_seq.to_be_bytes());
    }
}

impl Decode for DhtTeardown {
    fn decode(data: &[u8]) -> Result<Self, WireDecodeError> {
        let mut cursor = Cursor::new(data);

        let seq = cursor
            .read_u64::<BigEndian>()
            .map_err(|_| WireDecodeError)?;

        let mut key = [0u8; PUBLIC_KEY_SIZE];
        cursor.read_exact(&mut key).map_err(|_| WireDecodeError)?;

        let mut root = [0u8; PUBLIC_KEY_SIZE];
        cursor.read_exact(&mut root).map_err(|_| WireDecodeError)?;

        let root_seq = cursor
            .read_u64::<BigEndian>()
            .map_err(|_| WireDecodeError)?;

        Ok(Self {
            seq,
            key: PublicKeyBytes(key),
            root: PublicKeyBytes(root),
            root_seq,
        })
    }
}

#[derive(Debug, PartialEq, Hash, Eq)]
pub struct DhtInfo {
    seq: u64,
    key: PublicKeyBytes,
    peer: PeerId,
    rest: PeerId,
    root: PublicKeyBytes,
    root_seq: u64,
    timer: Instant, // Rust equivalent for time.Timer in Go, it's an Instant in time from which duration can be measured
}

impl DhtInfo {
    pub fn get_teardown(&self) -> DhtTeardown {
        DhtTeardown {
            seq: self.seq,
            key: self.key.clone(),
            root: self.root.clone(),
            root_seq: self.root_seq,
        }
    }

    pub fn get_map_key(&self) -> DhtMapKey {
        DhtMapKey {
            key: self.key.clone(),
            root: self.root.clone(),
            root_seq: self.root_seq,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct DhtMapKey {
    key: PublicKeyBytes,
    root: PublicKeyBytes,
    root_seq: u64,
}

// Rust equivalent of the treeLess function.
fn tree_less(key1: &PublicKeyBytes, key2: &PublicKeyBytes) -> bool {
    for (byte1, byte2) in key1.as_bytes().iter().zip(key2.as_bytes()) {
        match byte1.cmp(byte2) {
            cmp::Ordering::Less => return true,
            cmp::Ordering::Greater => return false,
            cmp::Ordering::Equal => (),
        }
    }
    false
}

// Rust equivalent of the dhtOrdered function.
fn dht_ordered(first: &PublicKeyBytes, second: &PublicKeyBytes, third: &PublicKeyBytes) -> bool {
    tree_less(first, second) && tree_less(second, third)
}
