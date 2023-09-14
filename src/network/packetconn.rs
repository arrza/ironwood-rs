use super::{
    core::Core,
    crypto::{Crypto, PublicKeyBytes},
    dhtree::{DhtTraffic, DhtreeHandle},
    wire::WireTraffic,
};
use crate::{
    network::crypto::{PUBLIC_KEY_SIZE, SIGNATURE_SIZE},
    types::{Addr, CloseChannelRx, Conn},
};
use ed25519_dalek::SecretKey;
use log::debug;
use std::{
    cmp::min,
    error::Error,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
use tokio::{select, sync::mpsc};

#[derive(Clone)]
pub struct PacketConn {
    pub core: Arc<Core>,
    closed: Arc<AtomicBool>,
}

pub type OobHandlerTx = mpsc::Sender<(PublicKeyBytes, PublicKeyBytes, Vec<u8>)>;
pub type OobHandlerRx = mpsc::Receiver<(PublicKeyBytes, PublicKeyBytes, Vec<u8>)>;

#[derive(Clone)]
pub struct PacketConnHandle {
    closed: Arc<AtomicBool>,
    recv_tx: mpsc::Sender<DhtTraffic>,
    crypto: Arc<Crypto>,
    oob_handler: Option<OobHandlerTx>,
}

pub struct PacketConnRead {
    recv: mpsc::Receiver<DhtTraffic>,
}

impl PacketConnRead {
    // The read_from method fulfills the net.PacketConn interface, with a types.Addr returned as the from address.
    // Note that failing to call read_from may cause the connection to block and/or leak memory.
    pub async fn read_from(&mut self, p: &mut [u8]) -> (usize, Addr) {
        debug!("++read_from.");
        let tr = self.recv.recv().await.unwrap();
        debug!("  read_from.1");
        let data = tr.payload.clone();
        let n = data.len();
        let n = min(n, p.len());
        p[..n].copy_from_slice(data.as_slice());
        let from = tr.source.addr();
        debug!("--read_from.");
        (n, from)
    }

    // MTU returns the maximum transmission unit of the PacketConn, i.e. maximum safe message size to send over the network.
    pub fn mtu(&self) -> u64 {
        const MAX_PEER_MESSAGE_SIZE: u64 = 65535;
        const MESSAGE_TYPE_SIZE: u64 = 1;
        const ROOT_SEQ_SIZE: u64 = 8;
        const TREE_UPDATE_OVERHEAD: u64 =
            MESSAGE_TYPE_SIZE + PUBLIC_KEY_SIZE as u64 + ROOT_SEQ_SIZE;
        const MAX_PORT_SIZE: u64 = 10; // maximum vuint size in bytes
        const TREE_HOP_SIZE: u64 = PUBLIC_KEY_SIZE as u64 + MAX_PORT_SIZE + SIGNATURE_SIZE as u64;
        const MAX_HOPS: u64 = (MAX_PEER_MESSAGE_SIZE - TREE_UPDATE_OVERHEAD) / TREE_HOP_SIZE;
        const MAX_PATH_BYTES: u64 = 2 * MAX_PORT_SIZE * MAX_HOPS; // to the root and back
        const PATH_TRAFFIC_OVERHEAD: u64 = MESSAGE_TYPE_SIZE
            + MAX_PATH_BYTES
            + PUBLIC_KEY_SIZE as u64
            + PUBLIC_KEY_SIZE as u64
            + MESSAGE_TYPE_SIZE;
        const MTU: u64 = MAX_PEER_MESSAGE_SIZE - PATH_TRAFFIC_OVERHEAD;
        MTU
    }
}

impl std::fmt::Debug for PacketConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Core: {:?}", self.core)
    }
}

impl PacketConn {
    pub fn new(
        secret: &SecretKey,
        oob_handler: Option<OobHandlerTx>,
    ) -> (PacketConn, PacketConnRead, DhtreeHandle) {
        let (recv_tx, recv) = mpsc::channel(10);
        let crypto = Arc::new(Crypto::new(secret));
        let closed = Arc::new(AtomicBool::new(false));
        let handle = PacketConnHandle {
            closed: closed.clone(),
            recv_tx: recv_tx.clone(),
            crypto: crypto.clone(),
            oob_handler,
        };

        let pconn_read = PacketConnRead { recv };
        let (core, mut dhtree, pathfinder) = Core::new(crypto, handle);
        tokio::spawn(async move {
            select! {
                _ = async move{dhtree.init().await;dhtree.handler().await;} => {} ,
                _ = pathfinder.handler() => {}
            }
        });
        let pconn = PacketConn {
            core: core.clone(),
            closed,
        };

        (pconn, pconn_read, core.dhtree.clone())
    }

    // The write_to method fulfills the net.PacketConn interface, with a types.Addr expected as the destination address.
    pub async fn write_to(&self, p: &[u8], addr: Addr) -> Result<usize, Box<dyn Error>> {
        debug!("++write_to");
        let dest = addr.into();
        if p.len() as u64 > self.mtu() {
            return Err("oversized message".into());
        }
        let tr = DhtTraffic {
            source: self.core.crypto.public_key.clone(),
            dest,
            kind: WireTraffic::Standard.into(),
            payload: p.to_vec(),
        };
        self.core.dhtree.send_traffic(tr);
        debug!("--write_to");
        Ok(p.len())
    }

    // Close shuts down the PacketConn.
    pub fn close(&self) -> Result<(), Box<dyn Error>> {
        self.closed.store(true, Ordering::SeqCst);
        Ok(())
    }

    // LocalAddr returns a types.Addr of the ed25519.PublicKey for this PacketConn.
    pub fn local_addr(&self) -> Addr {
        self.core.crypto.public_key.addr()
    }

    // HandleConn expects a peer's public key as its first argument, and a net.Conn with TCP-like semantics (reliable ordered delivery) as its second argument.
    // This function blocks while the net.Conn is in use, and returns an error if any occurs.
    // This function returns (almost) immediately if PacketConn.Close() is called.
    // In all cases, the net.Conn is closed before returning.
    pub async fn handle_conn(
        &self,
        key: PublicKeyBytes,
        conn: Box<dyn Conn>,
        prio: u8,
        mut close: CloseChannelRx,
    ) -> Result<(), Box<dyn Error>> {
        let pk = key;
        let core = self.core.clone();
        if core.crypto.public_key.eq(&pk) {
            return Err("attempted to connect to self".into());
        }
        let (p, conn) = core.peers.add_peer(pk, conn, prio).await?;
        select! {
            _ = conn.handler() => {},
            _ = close.recv() => {},
        }
        core.peers.remove_peer(p.port).await;
        Ok(())
    }

    // SendOutOfBand sends some out-of-band data to a key.
    // The data will be forwarded towards the destination key as far as possible, and then handled by the out-of-band handler of the terminal node.
    // This could be used to do e.g. key discovery based on an incomplete key, or to implement application-specific helpers for debugging and analytics.
    pub async fn send_out_of_band(
        &self,
        to_key: PublicKeyBytes,
        data: Vec<u8>,
    ) -> Result<(), Box<dyn Error>> {
        let tr = DhtTraffic {
            source: self.core.crypto.public_key.clone(),
            dest: to_key,
            kind: WireTraffic::OutOfBand.into(),
            payload: data,
        };
        self.core.dhtree.send_traffic(tr);
        Ok(())
    }

    // PrivateKey() returns the ed25519.PrivateKey used to initialize the PacketConn.
    pub fn private_key(&self) -> super::crypto::PrivateKeyBytes {
        self.core.crypto.private_key.clone()
    }

    // MTU returns the maximum transmission unit of the PacketConn, i.e. maximum safe message size to send over the network.
    pub fn mtu(&self) -> u64 {
        const MAX_PEER_MESSAGE_SIZE: u64 = 65535;
        const MESSAGE_TYPE_SIZE: u64 = 1;
        const ROOT_SEQ_SIZE: u64 = 8;
        const TREE_UPDATE_OVERHEAD: u64 =
            MESSAGE_TYPE_SIZE + PUBLIC_KEY_SIZE as u64 + ROOT_SEQ_SIZE;
        const MAX_PORT_SIZE: u64 = 10; // maximum vuint size in bytes
        const TREE_HOP_SIZE: u64 = PUBLIC_KEY_SIZE as u64 + MAX_PORT_SIZE + SIGNATURE_SIZE as u64;
        const MAX_HOPS: u64 = (MAX_PEER_MESSAGE_SIZE - TREE_UPDATE_OVERHEAD) / TREE_HOP_SIZE;
        const MAX_PATH_BYTES: u64 = 2 * MAX_PORT_SIZE * MAX_HOPS; // to the root and back
        const PATH_TRAFFIC_OVERHEAD: u64 = MESSAGE_TYPE_SIZE
            + MAX_PATH_BYTES
            + PUBLIC_KEY_SIZE as u64
            + PUBLIC_KEY_SIZE as u64
            + MESSAGE_TYPE_SIZE;
        const MTU: u64 = MAX_PEER_MESSAGE_SIZE - PATH_TRAFFIC_OVERHEAD;
        MTU
    }
}

impl PacketConnHandle {
    // IsClosed returns true if and only if the connection is closed.
    // This is to check if the PacketConn is closed without potentially being stuck on a blocking operation (e.g. a read or write).
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    // // SetOutOfBandHandler sets a function to handle out-of-band data.
    // // This function will be called every time out-of-band data is received.
    // // If no handler has been set, then any received out-of-band data is dropped.
    // pub async fn set_out_of_band_handler<F>(
    //     &mut self,
    //     handler: mpsc::Sender<(PublicKeyBytes, PublicKeyBytes, Vec<u8>)>,
    // ) -> Result<(), Box<dyn Error>>
    // where
    //     F: Fn(PublicKeyBytes, PublicKeyBytes, Vec<u8>) + 'static + Send + Sync,
    // {
    //     *self.oob_handler.lock().await = Some(handler);
    //     Ok(())
    // }

    pub async fn handle_traffic(&self, tr: DhtTraffic) {
        let kind = WireTraffic::from(tr.kind);
        debug!("++handle_traffic: {}", kind);
        match kind {
            WireTraffic::Dummy => {
                //Drop traffic
            }
            WireTraffic::Standard => {
                if self.is_closed() {}
                if !tr.dest.eq(&self.crypto.public_key) {
                    debug!(
                        "  handle_traffic: packet_dropped {} {}",
                        tr.dest, self.crypto.public_key
                    );
                } else if let Err(e) = self.recv_tx.send(tr).await {
                    debug!("  handle_traffic: Err({})", e);
                } else {
                    debug!("  handle_traffic: send_for_read");
                }
            }
            WireTraffic::OutOfBand => {
                if let Some(handler) = self.oob_handler.as_ref() {
                    let source = tr.source;
                    let dest = tr.dest;
                    let msg = tr.payload;
                    handler.send((source, dest, msg)).await;
                }
            }
        }
        debug!("--handle_traffic");
    }
}
