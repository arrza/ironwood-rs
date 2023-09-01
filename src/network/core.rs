use std::sync::Arc;

use super::{
    crypto::Crypto,
    dhtree::{Dhtree, DhtreeHandle},
    packetconn::PacketConnHandle,
    pathfinder::{Pathfinder, PathfinderHandle},
    peers::{Peers, PeersHandle},
};

//#[derive(Debug)]
pub struct Core {
    pub crypto: Arc<Crypto>,
    pub dhtree: DhtreeHandle,
    pub peers: PeersHandle,
    pub pconn: PacketConnHandle,
    pub pathfinder: PathfinderHandle,
}

impl std::fmt::Debug for Core {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Crypto:\n {:?} \n", self.crypto)?;
        write!(f, "Dhtree:\n {:?} \n", self.dhtree)?;
        write!(f, "Peers:\n {:?} \n", self.peers)?;
        write!(f, "Pathfinder:\n {:?} \n", self.pathfinder)
    }
}

impl Core {
    pub fn new(crypto: Arc<Crypto>, pconn: PacketConnHandle) -> (Arc<Self>, Dhtree, Pathfinder) {
        let (dhtree, dht_queue) = Dhtree::new();
        let (pathfinder, pf_queue) = Pathfinder::new(dhtree.clone(), crypto.clone());
        let (peers, peers_handle) = Peers::new(crypto.clone(), dhtree.clone(), pathfinder.clone());
        let core = Self {
            crypto,
            dhtree: dhtree.clone(),
            peers: peers_handle,
            pconn,
            pathfinder: pathfinder.clone(),
        };
        let core = Arc::new(core);
        let dhtree = Dhtree::build(core.clone(), pathfinder.clone(), dhtree, dht_queue, peers);
        let pf = Pathfinder::build(core.clone(), pathfinder, pf_queue);
        (core, dhtree, pf)
    }
}
