use crate::{
    network::{
        crypto::{PublicKeyBytes, SignatureBytes, PUBLIC_KEY_SIZE, SIGNATURE_SIZE},
        dhtree::{DhtTraffic, TreeLabel},
        wire::{encode_path, Decode, Encode, WireDecodeError},
    },
    types::PeerPort,
};
use integer_encoding::{VarInt, VarIntReader};
use log::debug;
use std::{
    collections::HashMap,
    fmt,
    io::{Cursor, Read},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::{mpsc, Mutex};

use super::{core::Core, crypto::Crypto, dhtree::DhtreeHandle, peers::PeerId};

const PATHFINDER_TIMEOUT: Duration = Duration::from_secs(60);
const PATHFINDER_THROTTLE: Duration = Duration::from_secs(1);

#[derive(Debug, Clone)]
pub struct PathInfo {
    ltime: Instant,
    ntime: Instant,
    path: Vec<PeerPort>,
}

#[derive(Debug)]
enum PathfinderMessages {
    DoNotify(PublicKeyBytes, bool),
    HandleNotify(PathNotify),
    HandleLookup(PathLookup),
}

#[derive(Debug)]
pub struct Pathfinder {
    core: Arc<Core>,
    crypto: Arc<Crypto>,
    dhtree: DhtreeHandle,
    paths: Arc<Mutex<HashMap<PublicKeyBytes, PathInfo>>>,
    queue: mpsc::Receiver<PathfinderMessages>,
    queue_tx: mpsc::Sender<PathfinderMessages>,
}

#[derive(Clone, Debug)]
pub struct PathfinderHandle {
    crypto: Arc<Crypto>,
    dhtree: DhtreeHandle,
    paths: Arc<Mutex<HashMap<PublicKeyBytes, PathInfo>>>,
    queue: mpsc::Sender<PathfinderMessages>,
}

#[derive(Debug)]
pub struct PathfinderQueue {
    queue: mpsc::Receiver<PathfinderMessages>,
}

impl PathfinderHandle {
    pub async fn get_path(&self, dest: &PublicKeyBytes) -> Option<Vec<PeerPort>> {
        let info;
        {
            let mut paths = self.paths.lock().await;
            if let Some(_info) = paths.get_mut(&dest) {
                // if the path exists, stop the previous timer
                //info.timer_handle.take().map(|handle| handle.abort());
            } else {
                // otherwise, create a new path info
                let info = PathInfo {
                    ltime: Instant::now() - PATHFINDER_THROTTLE,
                    ntime: Instant::now() - PATHFINDER_THROTTLE,
                    path: vec![], // you need to replace this with the actual path
                };
                paths.insert(dest.clone(), info);
            }

            info = paths.get(&dest).cloned().unwrap();
        }
        // let dest_clone = dest.clone();

        // let paths = self.paths.clone();
        // // Spawn a new timer task, which will delete the path after pathfinderTIMEOUT
        // let _timer_handle = tokio::spawn(async move {
        //     tokio::time::sleep(Duration::from_secs(60)).await; // equivalent to pathfinderTIMEOUT
        //     let mut paths = paths.lock().await;
        //     paths.remove(&dest_clone);
        // });

        //info.timer_handle = Some(timer_handle);

        Some(info.path)
    }
    pub async fn handle_notify(&self, n: PathNotify) {
        self.queue.send(PathfinderMessages::HandleNotify(n)).await;
    }
    pub async fn do_notify(&self, dest: &PublicKeyBytes, keep_alive: bool) {
        self.queue
            .send(PathfinderMessages::DoNotify(dest.clone(), keep_alive))
            .await;
    }

    fn get_response(&self, l: &PathLookup) -> Option<PathResponse> {
        // Check if lookup comes from us
        let dest = l.notify.label.as_ref().unwrap().key.clone();
        if dest != self.crypto.public_key || !l.notify.check() {
            // TODO? skip l.notify.check()? only check the last hop?
            return None;
        }

        let mut r = PathResponse {
            from: self.crypto.public_key.clone(),
            path: l.rpath.iter().rev().cloned().collect(),
            rpath: Vec::new(),
        };
        r.path.push(0);
        return Some(r);
    }

    async fn get_lookup(&self, n: &PathNotify) -> Option<PathLookup> {
        let mut paths = self.paths.lock().await;
        if let Some(info) = paths.get_mut(&n.label.as_ref().unwrap().key) {
            if info.ltime.elapsed() < PATHFINDER_THROTTLE || !n.check() {
                return None;
            }
            let l = PathLookup {
                notify: n.clone(),
                rpath: Vec::new(),
            };
            info.ltime = Instant::now();
            return Some(l);
        }
        None
    }

    pub async fn handle_response(&self, r: &PathResponse) {
        debug!("++handle_response.");
        // Note: this only handles the case where there's no valid next hop in the path
        let mut paths = self.paths.lock().await;
        if let Some(info) = paths.get_mut(&r.from) {
            // Reverse r.rpath and save it to info.path
            info.path.clear();
            for idx in (0..r.rpath.len()).rev() {
                info.path.push(r.rpath[idx]);
            }
            info.path.push(PeerPort::default()); // equivalent to append(0)
        }
        debug!("--handle_response.");
    }

    pub async fn handle_lookup(&self, l: PathLookup) {
        debug!("++handle_lookup");
        self.queue.send(PathfinderMessages::HandleLookup(l)).await;
        debug!("--handle_lookup");
    }
}

impl Pathfinder {
    pub fn new(dhtree: DhtreeHandle, crypto: Arc<Crypto>) -> (PathfinderHandle, PathfinderQueue) {
        let (queue_tx, queue_rx) = mpsc::channel(10);
        let handle = PathfinderHandle {
            paths: Arc::new(Mutex::new(HashMap::new())),
            dhtree,
            queue: queue_tx,
            crypto,
        };
        (handle, PathfinderQueue { queue: queue_rx })
    }

    pub fn build(core: Arc<Core>, handle: PathfinderHandle, queue: PathfinderQueue) -> Pathfinder {
        Pathfinder {
            core,
            dhtree: handle.dhtree.clone(),
            paths: handle.paths.clone(),
            queue: queue.queue,
            queue_tx: handle.queue,
            crypto: handle.crypto,
        }
    }

    pub async fn handler(mut self) {
        while let Some(msg) = self.queue.recv().await {
            match msg {
                PathfinderMessages::DoNotify(dest, keep_alive) => {
                    self.do_notify(&dest, keep_alive).await
                }
                PathfinderMessages::HandleNotify(n) => self.handle_notify(n).await,
                PathfinderMessages::HandleLookup(l) => self.handle_lookup(l).await,
            }
        }
    }

    pub fn handle(&self) -> PathfinderHandle {
        PathfinderHandle {
            dhtree: self.dhtree.clone(),
            paths: self.paths.clone(),
            queue: self.queue_tx.clone(),
            crypto: self.crypto.clone(),
        }
    }

    async fn get_notify(&self, dest: &PublicKeyBytes, keep_alive: bool) -> Option<PathNotify> {
        debug!("++get_notify");
        let throttle = if keep_alive {
            PATHFINDER_TIMEOUT
        } else {
            PATHFINDER_THROTTLE
        };

        let dhtree = self.dhtree.clone();
        let mut paths = self.paths.lock().await;
        debug!("  get_notify. lock");
        if let Some(info) = paths.get_mut(&dest) {
            if info.ntime.elapsed() > throttle {
                let mut n = PathNotify {
                    sig: SignatureBytes::default(),
                    dest: dest.clone(),
                    label: Some(dhtree.get_label().await),
                };
                debug!("  get_notify. path not");

                let mut bytes = Vec::new();
                n.label.as_ref().unwrap().encode(&mut bytes);
                let mut bs = Vec::new();
                bs.extend_from_slice(dest.as_bytes());
                bs.extend_from_slice(&bytes);
                n.sig = self.core.crypto.private_key.sign(&bs);
                info.ntime = Instant::now();
                debug!("--get_notify (Some)");
                return Some(n);
            }
        }
        debug!("--get_notify (None)");
        None
    }

    async fn handle_notify(&self, n: PathNotify) {
        debug!("++handle_notify");
        let core = self.core.clone();
        let dhtree = self.dhtree.clone();
        let self_clone = self.handle();
        tokio::spawn(async move {
            let pid = dhtree.dht_lookup(n.dest.clone(), false).await;
            if pid != PeerId::nil() {
                let next = core.peers.get_peer(pid).await;
                next.send_path_notify(n).unwrap();
            } else if let Some(l) = self_clone.get_lookup(&n).await {
                self_clone.handle_lookup(l).await;
            }
        });
        debug!("--handle_notify");
    }

    pub async fn handle_lookup(&self, l: PathLookup) {
        debug!("++handle_lookup");
        // TODO? check the tree_label at some point
        let core = self.core.clone();
        let dhtree = self.dhtree.clone();
        let self_clone = self.handle();
        //tokio::spawn(async move {
        let pid = dhtree
            .tree_lookup(l.notify.label.as_ref().unwrap().clone())
            .await;
        if pid != PeerId::nil() {
            let next = core.peers.get_peer(pid).await;
            next.send_path_lookup(l).unwrap();
        } else if let Some(r) = self_clone.get_response(&l) {
            core.peers.handle_path_response(r);
        }
        //});
        debug!("--handle_lookup");
    }

    async fn do_notify(&self, dest: &PublicKeyBytes, keep_alive: bool) {
        if let Some(n) = self.get_notify(dest, keep_alive).await {
            self.handle_notify(n).await;
        }
    }
}

#[derive(Debug)]
pub struct PathTraffic {
    pub path: Vec<PeerPort>,
    pub dt: DhtTraffic,
}

impl fmt::Display for PathTraffic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let path = self
            .path
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<String>>()
            .join(", ");
        write!(f, "PathTraffic {{ path: [{}], dt: {} }}", path, self.dt)
    }
}

impl Encode for PathTraffic {
    fn encode(&self, out: &mut Vec<u8>) {
        let mut path = self.path.clone();
        debug!("Path: {:?}", path);
        // if path.last().is_none() || path.last().unwrap() != &0 {
        //     path.push(0);
        // }

        encode_path(&path, out);

        debug!("Out: {:?}", out);
        // Encode dt
        self.dt.encode(out);
    }
}

impl Decode for PathTraffic {
    fn decode(data: &[u8]) -> Result<Self, WireDecodeError> {
        let mut cursor = Cursor::new(data);

        // Reading path
        let mut path = Vec::new();
        while cursor.position() < data.len() as u64 {
            let peer_port: u64 = cursor.read_varint().map_err(|_| WireDecodeError)?;
            path.push(peer_port);
            if peer_port == 0 {
                break;
            }
        }

        // Reading dt
        let remaining_data = &data[cursor.position() as usize..];
        let dt = DhtTraffic::decode(remaining_data)?;

        Ok(Self { path, dt })
    }
}

#[derive(Clone, Debug)]
pub struct PathNotify {
    sig: SignatureBytes,
    dest: PublicKeyBytes,
    label: Option<TreeLabel>,
}

impl PathNotify {
    pub fn check(&self) -> bool {
        match &self.label {
            None => false,
            Some(label) => {
                if !label.check() {
                    debug!("Invalid label");
                    return false;
                }
                let mut bs = Vec::new();
                bs.extend_from_slice(self.dest.as_bytes());
                label.encode(&mut bs);
                let dest = label.key.clone();
                if !dest.verify(&bs, &self.sig.as_bytes()) {
                    panic!("Invalid Notify");
                    return false;
                }
                true
            }
        }
    }
}

impl fmt::Display for PathNotify {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PathNotify {{ sig: {}, dest: {}, label: {} }}",
            self.sig,
            self.dest,
            self.label
                .as_ref()
                .map_or_else(|| "None".to_string(), |label| label.to_string())
        )
    }
}

impl Encode for PathNotify {
    fn encode(&self, out: &mut Vec<u8>) {
        // Encode sig
        out.extend_from_slice(self.sig.as_bytes());

        // Encode dest
        out.extend_from_slice(self.dest.as_bytes());

        // Encode label if it exists
        if let Some(label) = &self.label {
            label.encode(out);
        }
    }
}

impl Decode for PathNotify {
    fn decode(data: &[u8]) -> Result<Self, WireDecodeError> {
        let mut cursor = Cursor::new(data);

        let mut sig = [0u8; SIGNATURE_SIZE];
        cursor.read_exact(&mut sig).map_err(|_| WireDecodeError)?;

        let mut dest = [0u8; PUBLIC_KEY_SIZE];
        cursor.read_exact(&mut dest).map_err(|_| WireDecodeError)?;

        let label = if cursor.position() < data.len() as u64 {
            Some(TreeLabel::decode(&data[cursor.position() as usize..])?)
        } else {
            None
        };

        Ok(Self {
            sig: SignatureBytes(sig),
            dest: PublicKeyBytes(dest),
            label,
        })
    }
}

#[derive(Debug, Clone)]
pub struct PathResponse {
    from: PublicKeyBytes,
    pub path: Vec<PeerPort>,
    pub rpath: Vec<PeerPort>,
}

impl fmt::Display for PathResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PathResponse {{ from: {}, path: {:?}, rpath: {:?} }}",
            self.from, self.path, self.rpath
        )
    }
}

impl Encode for PathResponse {
    fn encode(&self, out: &mut Vec<u8>) {
        // Encode from
        out.extend_from_slice(self.from.as_bytes());

        // let mut path = self.path.clone();
        // if path.last().is_none() || path.last().unwrap() != &0 {
        //     path.push(0);
        // }

        // Encode path
        encode_path(&self.path, out);

        // let mut path = self.rpath.clone();
        // if path.last().is_none() || path.last().unwrap() != &0 {
        //     path.push(0);
        // }
        // Encode rpath
        encode_path(&self.rpath, out);
    }
}

impl Decode for PathResponse {
    fn decode(data: &[u8]) -> Result<Self, WireDecodeError> {
        let mut cursor = Cursor::new(data);

        let mut from = [0u8; PUBLIC_KEY_SIZE];
        cursor.read_exact(&mut from).map_err(|_| WireDecodeError)?;

        let mut path = Vec::new();
        while let Ok(peer_port) = cursor.read_varint() {
            path.push(peer_port);
            if peer_port == 0 {
                break;
            }
        }

        let mut rpath = Vec::new();
        while let Ok(peer_port) = cursor.read_varint() {
            rpath.push(peer_port);
            if peer_port == 0 {
                break;
            }
        }

        Ok(Self {
            from: PublicKeyBytes(from),
            path,
            rpath,
        })
    }
}

#[derive(Debug, Clone)]
pub struct PathLookup {
    notify: PathNotify,
    pub rpath: Vec<PeerPort>,
}

impl fmt::Display for PathLookup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PathLookup {{ notify: {}, rpath: {:?} }}",
            self.notify, self.rpath
        )
    }
}

impl Encode for PathLookup {
    fn encode(&self, out: &mut Vec<u8>) {
        let mut notify_out = Vec::new();
        self.notify.encode(&mut notify_out);
        let notify_length = notify_out.len() as u64;
        out.extend_from_slice(&notify_length.encode_var_vec());
        out.extend_from_slice(&notify_out);

        // Encode rpath
        encode_path(&self.rpath, out);
    }
}

impl Decode for PathLookup {
    fn decode(data: &[u8]) -> Result<Self, WireDecodeError> {
        debug!("++decode");
        let mut cursor = Cursor::new(data);

        let notify_length: u64 = cursor.read_varint().map_err(|_| WireDecodeError)?;
        let pos = cursor.position() as usize;
        let notify_data = &data[pos..pos + notify_length as usize];
        let notify = PathNotify::decode(notify_data)?;

        let rpath_data = &data[pos + notify_length as usize..];
        let mut rpath = Vec::new();
        debug!("++decode.1");
        let mut cursor = Cursor::new(rpath_data);
        while let Ok(peer_port) = cursor.read_varint() {
            rpath.push(peer_port);
            if peer_port == 0 {
                break;
            }
        }
        debug!("++decode.2");
        let rpath_data = &rpath_data[cursor.position() as usize..];
        if !rpath_data.is_empty()
        /*|| (rpath.len() > 0&& *rpath.last().unwrap() == 0)*/
        {
            return Err(WireDecodeError);
        }

        debug!("--decode");
        Ok(Self { notify, rpath })
    }
}
