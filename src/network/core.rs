use std::sync::{Arc, Weak};

use super::{crypto::Crypto, dhtree::Dhtree, packetconn::PacketConnHandle, peers::Peers};

//#[derive(Debug)]
pub struct Core {
    pub crypto: Arc<Crypto>,
    pub dhtree: Arc<Dhtree>,
    pub peers: Arc<Peers>,
    pub pconn: PacketConnHandle,
}

impl std::fmt::Debug for Core {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Crypto:\n {:?} \n", self.crypto)?;
        write!(f, "Dhtree:\n {:?} \n", self.dhtree)?;
        write!(f, "Peers:\n {:?} \n", self.peers)
    }
}

impl Core {
    pub fn new(crypto: Arc<Crypto>, pconn: PacketConnHandle) -> Arc<Self> {
        let core = Arc::new_cyclic(|weak_core| {
            // Initialize components with the weak reference to Core
            let dhtree = Dhtree::new(weak_core.clone());
            let peers = Peers::new(weak_core.clone());

            // Return the Core instance
            Core {
                crypto: crypto.clone(),
                dhtree,
                peers,
                pconn,
            }
        });
        core.dhtree.init();
        core
    }
}
