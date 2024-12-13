use super::{
    core::Core,
    crypto::PublicKeyBytes,
    dhtree::{DhtBootstrap, DhtBootstrapAck, DhtSetup, DhtTeardown, DhtTraffic, TreeInfo},
    pathfinder::{PathLookup, PathNotify, PathResponse, PathTraffic},
    wire::{Decode, Encode, Wire},
};
use crate::types::{Conn, PeerPort};
use log::debug;
use std::{
    collections::HashMap,
    error::Error,
    fmt,
    hash::Hash,
    sync::{
        atomic::{self, AtomicU64, AtomicU8},
        Arc, Mutex, RwLock, Weak,
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    select,
    sync::mpsc,
    time::timeout,
};

pub const PEER_KEEPALIVE: Duration = Duration::from_secs(4);
pub const PEER_TIMEOUT: Duration = Duration::from_secs(6);

pub struct Peers {
    self_ref: Weak<Peers>,
    core: Weak<Core>,
    peers: Arc<RwLock<HashMap<PeerPort, Arc<Peer>>>>,
    last_id: Arc<AtomicU64>,
}

impl std::fmt::Debug for Peers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Peers{{ last_id:{} ,",
            self.last_id.load(atomic::Ordering::SeqCst)
        )?;
        for p in self.peers.read().unwrap().iter() {
            write!(f, "id:{} peers: {:?}, ", p.0, p.1)?;
        }
        write!(f, " }}")
    }
}

impl Peers {
    pub fn new(core: Weak<Core>) -> Arc<Self> {
        Arc::new_cyclic(|weak_peers| Peers {
            self_ref: weak_peers.clone(),
            core,
            peers: Arc::new(RwLock::new(HashMap::new())),
            last_id: Arc::new(AtomicU64::new(1)),
        })
    }

    fn core(&self) -> Arc<Core> {
        self.core.upgrade().unwrap()
    }

    pub fn get_peer(&self, pid: PeerId) -> Option<Arc<Peer>> {
        for (_, p) in self.peers.read().unwrap().iter() {
            if p.id == pid {
                return Some(p.clone());
            }
        }
        //panic!("Peer {pid} not found!");
        None
    }

    pub fn add_peer(
        &self,
        key: PublicKeyBytes,
        conn: Box<dyn Conn>,
        prio: u8,
    ) -> Result<(Arc<Peer>, PeerConnection), Box<dyn Error>> {
        let mut idx = self.peers.read().unwrap().len() as u64;
        for i in 1.. {
            if !self.peers.read().unwrap().contains_key(&i) {
                idx = i;
                break;
            }
        }
        let (wq_tx, wq_rx) = mpsc::unbounded_channel();
        let id = PeerId(self.last_id.fetch_add(1, atomic::Ordering::SeqCst));
        let peer = Peer {
            peers: self.self_ref.upgrade().unwrap(),
            key,
            port: idx,
            prio: AtomicU8::new(prio),
            ready: true,
            remote_addr: conn.peer_addr().unwrap().to_string(),
            info: Arc::new(Mutex::new(None)),
            id,
            write_queue: wq_tx,
        };
        let peer = Arc::new(peer);
        let conn = PeerConnection {
            id,
            conn,
            peer: peer.clone(),
            write_queue: wq_rx,
        };
        self.peers.write().unwrap().insert(idx, peer.clone());
        Ok((peer, conn))
    }

    pub fn remove_peer(&self, port: PeerPort) -> Result<(), Box<dyn Error>> {
        match self.peers.write().unwrap().remove(&port) {
            Some(_) => Ok(()),
            None => Err("peer not found".into()),
        }
    }

    pub async fn handle_path_response(&self, mut response: PathResponse) {
        debug!("++handle_path_response");
        let mut next_port: Option<PeerPort> = None;

        if !response.path.is_empty() {
            next_port = Some(response.path.remove(0));
        }

        match next_port {
            Some(port) => {
                debug!("  handle_path_response.1");
                let next = { self.peers.read().unwrap().get(&port).cloned() };
                if let Some(next) = next {
                    next.send_path_response(response);
                } else {
                    self.core()
                        .dhtree
                        .pathfinder
                        .handle_response(&response)
                        .await;
                }
            }
            None => {
                debug!("  handle_path_response.2");
                self.core()
                    .dhtree
                    .pathfinder
                    .handle_response(&response)
                    .await;
            }
        }
        debug!("--handle_path_response");
    }

    pub async fn handle_path_traffic(&self, mut tr: PathTraffic) -> Result<(), Box<dyn Error>> {
        debug!("++handle_path_traffic");
        let mut next_port: Option<PeerPort> = None;
        debug!("Path: {:?}", tr.path);
        if !tr.path.is_empty() {
            next_port = Some(tr.path.remove(0));
        }

        match next_port {
            Some(port) => {
                let next = { self.peers.read().unwrap().get(&port).cloned() };
                if let Some(next) = next {
                    debug!("  handle_path_traffic.1");
                    // Forward using the source routed path
                    next.send_path_traffic(tr)?;
                } else {
                    debug!("  handle_path_traffic.2");
                    // Fall back to dhtTraffic
                    self.core().dhtree.handle_dht_traffic(tr.dt, false).await;
                }
            }
            None => {
                // Fall back to dhtTraffic
                self.core().dhtree.handle_dht_traffic(tr.dt, false).await;
            }
        }
        debug!("--handle_path_traffic");
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PeerId(u64);

impl PeerId {
    pub fn nil() -> PeerId {
        PeerId(0)
    }
    pub fn is_nil(&self) -> bool {
        self.0 == 0
    }
}

impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PeerId({})", self.0)
    }
}

#[derive(Debug)]
pub struct PeerConnection {
    id: PeerId,
    conn: Box<dyn Conn>,
    peer: Arc<Peer>,
    write_queue: mpsc::UnboundedReceiver<Vec<u8>>,
}

impl PeerConnection {
    pub async fn write(&mut self, bs: &[u8]) -> std::io::Result<()> {
        self.conn.write_all(bs).await
    }

    pub async fn handler(mut self) -> Result<(), Box<dyn std::error::Error>> {
        println!("Sending Tree");
        self.peer.send_tree(&TreeInfo::new(
            self.peer.peers.core().crypto.public_key.clone(),
        ))?;
        let (mut conn_rx, mut conn_tx) = self.conn.split(); //elf.conn.split();
        let prio = self.peer.prio.load(atomic::Ordering::SeqCst);
        if prio > 0 {
            // Write to stream
            conn_tx.write_all(&[0x00, 0x03, b'p', prio]).await?;
        }

        let mut len_buf = [0; 2];
        let mut bs = vec![0; 65535];
        let peer = self.peer.clone();
        let rx_task = async move {
            loop {
                timeout(PEER_TIMEOUT, conn_rx.read_exact(&mut len_buf)).await??;
                let size = u16::from_be_bytes(len_buf);
                bs.resize(size as usize, 0);
                conn_rx.read_exact(&mut bs).await?;
                debug!("recv len: {}", size);
                peer.handle_packet(&bs).await.unwrap();
            }
            Result::<_, Box<dyn Error>>::Ok(())
        };

        let tx_task = async move {
            loop {
                match timeout(PEER_KEEPALIVE, self.write_queue.recv()).await {
                    Ok(Some(data)) => {
                        timeout(PEER_TIMEOUT, conn_tx.write_all(&data)).await??;
                    }
                    Err(_) => {
                        timeout(
                            PEER_TIMEOUT,
                            conn_tx.write_all(&[0x00, 0x01, Wire::Dummy.into()]),
                        )
                        .await??;
                    }
                    _ => {
                        break;
                    }
                }
            }
            Result::<_, Box<dyn Error>>::Ok(())
        };

        select! {
            res = rx_task => {debug!("PeerConnection RxTask Finished ({:?}).",res);},
            res = tx_task => {debug!("PeerConnection TxTask Finished ({:?}).",res);}
        }
        if self.peer.info.lock().unwrap().is_some() {
            self.peer.peers.core().dhtree.remove(self.id).await;
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct Peer {
    pub id: PeerId,
    peers: Arc<Peers>,
    pub key: PublicKeyBytes,
    pub info: Arc<Mutex<Option<TreeInfo>>>,
    pub port: PeerPort,
    ready: bool,
    pub prio: AtomicU8,
    pub remote_addr: String,
    write_queue: mpsc::UnboundedSender<Vec<u8>>,
}

impl Peer {
    pub fn send_packet<T: Encode>(&self, p_type: u8, data: &T) -> Result<(), Box<dyn Error>> {
        let mut write_buf = Vec::with_capacity(65536);
        write_buf.clear();
        write_buf.push(0x00);
        write_buf.push(0x00);

        write_buf.push(p_type);
        data.encode(&mut write_buf);

        let bs = &write_buf[2..];

        if bs.len() > (u16::MAX as usize) {
            return Err("Invalid data send".into());
        }

        let len_bs = (bs.len() as u16).to_be_bytes();

        write_buf[0..2].copy_from_slice(&len_bs);

        self.write_queue.send(write_buf)?;
        debug!("Packet Type Tx: {}", Wire::from(p_type));
        Ok(())
    }

    async fn handle_packet(&self, bs: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        if bs.is_empty() {
            return Err("empty packet".into());
        }
        debug!("Packet Type Rx: {}", Wire::from(bs[0]));
        match Wire::from(bs[0]) {
            Wire::Dummy => self.handle_dummy(&bs[1..]),
            Wire::ProtoTree => self.handle_tree(&bs[1..]).await,
            Wire::ProtoDHTBootstrap => self.handle_bootstrap(&bs[1..]).await,
            Wire::ProtoDHTBootstrapAck => self.handle_bootstrap_ack(&bs[1..]).await,
            Wire::ProtoDHTSetup => self.handle_setup(&bs[1..]).await,
            Wire::ProtoDHTTeardown => self.handle_teardown(&bs[1..]).await,
            Wire::ProtoPathNotify => self.handle_path_notify(&bs[1..]).await,
            Wire::ProtoPathLookup => self.handle_path_lookup(&bs[1..]).await,
            Wire::ProtoPathResponse => self.handle_path_response(&bs[1..]).await,
            Wire::DHTTraffic => self.handle_dht_traffic(&bs[1..]).await,
            Wire::PathTraffic => self.handle_path_traffic(&bs[1..]).await,
        }
    }

    fn handle_dummy(&self, bs: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        if bs.len() < 2 {
            return Ok(());
        }
        if bs[0] == b'p' {
            let prio = bs[1];
            if prio > self.prio.load(atomic::Ordering::SeqCst) {
                self.prio.store(prio, atomic::Ordering::SeqCst);
            }
        }

        Ok(())
    }

    async fn handle_tree(&self, bs: &[u8]) -> Result<(), Box<dyn Error>> {
        let info = TreeInfo::decode(bs)?;
        debug!("RX: {} {}", self.id, info);
        if !info.check_sigs() {
            return Err(String::from("Invalid signature").into());
        }

        if self.key != info.from() {
            return Err(String::from("Unrecognized public key").into());
        }

        let dest = info.hops.last().unwrap().next.clone();

        if self.peers.core().crypto.public_key != dest {
            return Err(String::from("Incorrect destination").into());
        }

        *self.info.lock().unwrap() = Some(info.clone());

        self.peers.core().dhtree.update(info, self.id).await;

        Ok(())
    }

    pub fn send_tree(&self, info: &TreeInfo) -> Result<(), Box<dyn Error>> {
        let updated_info = info.add(self.peers.core().crypto.private_key.clone(), self);
        debug!("TX: {} {}", self.id, info);
        self.send_packet(Wire::ProtoTree as u8, &updated_info)
    }

    pub async fn handle_bootstrap(&self, bs: &[u8]) -> Result<(), Box<dyn Error>> {
        let bootstrap = DhtBootstrap::decode(bs)?;
        debug!("RX: {} {}", self.id, bootstrap);
        self.peers.core().dhtree.handle_bootstrap(&bootstrap).await;
        Ok(())
    }

    pub fn send_bootstrap(&self, bootstrap: &DhtBootstrap) -> Result<(), Box<dyn Error>> {
        debug!("TX: {} {}", self.id, bootstrap);
        self.send_packet(Wire::ProtoDHTBootstrap as u8, bootstrap)
    }

    pub async fn handle_bootstrap_ack(&self, bs: &[u8]) -> Result<(), Box<dyn Error>> {
        let ack = DhtBootstrapAck::decode(bs)?;
        debug!("RX: {} {}", self.id, ack);
        self.peers.core().dhtree.handle_bootstrap_ack(&ack).await;
        Ok(())
    }

    pub fn send_bootstrap_ack(&self, ack: &DhtBootstrapAck) -> Result<(), Box<dyn Error>> {
        debug!("TX: {} {}", self.id, ack);
        self.send_packet(Wire::ProtoDHTBootstrapAck as u8, ack)
    }

    pub async fn handle_setup(&self, bs: &[u8]) -> Result<(), Box<dyn Error>> {
        let setup = DhtSetup::decode(bs)?;
        debug!("RX: {} {}", self.id, setup);
        if !setup.check() {
            return Err("Invalid setup".into());
        }
        self.peers.core().dhtree.handle_setup(self.id, &setup).await;
        Ok(())
    }

    pub async fn send_setup(&self, setup: &DhtSetup) -> Result<(), Box<dyn Error>> {
        debug!("TX: {} {}", self.id, setup);
        self.send_packet(Wire::ProtoDHTSetup as u8, setup)
    }

    pub async fn handle_teardown(&self, bs: &[u8]) -> Result<(), Box<dyn Error>> {
        debug!("++handle_teardown");
        let teardown = DhtTeardown::decode(bs)?;
        debug!("RX: {} {}", self.id, teardown);
        self.peers.core().dhtree.teardown(self.id, &teardown).await;
        debug!("--handle_teardown");
        Ok(())
    }

    pub fn send_teardown(&self, teardown: &DhtTeardown) -> Result<(), Box<dyn Error>> {
        debug!("TX: {} {}", self.id, teardown);
        self.send_packet(Wire::ProtoDHTTeardown as u8, teardown)
    }

    pub async fn handle_path_notify(&self, bs: &[u8]) -> Result<(), Box<dyn Error>> {
        let notify = PathNotify::decode(bs)?;
        debug!("RX: {} {}", self.id, notify);
        self.peers
            .core()
            .dhtree
            .pathfinder
            .handle_notify(notify)
            .await;
        Ok(())
    }

    pub fn send_path_notify(&self, notify: PathNotify) -> Result<(), Box<dyn Error>> {
        debug!("TX: {} {}", self.id, notify);
        self.send_packet(Wire::ProtoPathNotify as u8, &notify)
    }

    pub async fn handle_path_lookup(&self, bs: &[u8]) -> Result<(), Box<dyn Error>> {
        debug!("++handle_path_lookup");
        let mut lookup = PathLookup::decode(bs).map_err(|e| {
            debug!("Can not decode");
            e
        })?;
        debug!("RX: {} {}", self.id, lookup);
        if !lookup.notify.check() {
            debug!("Invalid Notify");
            return Ok(());
        } else {
            debug!("Notify Ok");
        }
        lookup.rpath.push(self.port);
        self.peers
            .core()
            .dhtree
            .pathfinder
            .handle_lookup(lookup)
            .await;
        debug!("--handle_path_lookup");
        Ok(())
    }

    pub fn send_path_lookup(&self, lookup: PathLookup) -> Result<(), Box<dyn Error>> {
        debug!("TX: {} {}", self.id, lookup);
        self.send_packet(Wire::ProtoPathLookup as u8, &lookup)
    }

    pub async fn handle_path_response(&self, bs: &[u8]) -> Result<(), Box<dyn Error>> {
        let mut response = PathResponse::decode(bs)?;
        debug!("RX: {} {}", self.id, response);
        response.rpath.push(self.port);
        debug!("PathResponse: {}", response);
        self.peers.handle_path_response(response).await;
        Ok(())
    }

    pub fn send_path_response(&self, response: PathResponse) -> Result<(), Box<dyn Error>> {
        debug!("TX: {} {}", self.id, response);
        self.send_packet(Wire::ProtoPathResponse as u8, &response)
    }

    pub async fn handle_dht_traffic(&self, bs: &[u8]) -> Result<(), Box<dyn Error>> {
        let tr = DhtTraffic::decode(bs)?;
        debug!("RX: {} {}", self.id, tr);
        self.peers.core().dhtree.handle_dht_traffic(tr, true).await;
        Ok(())
    }

    pub fn send_dht_traffic(&self, tr: DhtTraffic) -> Result<(), Box<dyn Error>> {
        debug!("TX: {} {}", self.id, tr);
        self.send_packet(Wire::DHTTraffic as u8, &tr)
    }

    pub async fn handle_path_traffic(&self, bs: &[u8]) -> Result<(), Box<dyn Error>> {
        let tr = PathTraffic::decode(bs)?;
        debug!("RX: {} {}", self.id, tr);
        self.peers.handle_path_traffic(tr).await;
        Ok(())
    }

    pub fn send_path_traffic(&self, tr: PathTraffic) -> Result<(), Box<dyn Error>> {
        debug!("TX: {} {}", self.id, tr);
        self.send_packet(Wire::PathTraffic as u8, &tr)
    }
}
