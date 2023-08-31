use super::{
    crypto::{to_box_priv, BoxPriv, EdPriv, EdPub},
    network::{NetManager, NetManagerHandle, NetManagerRead},
    session::{SessionManager, SessionManagerHandle, SESSION_TRAFFIC_OVERHEAD},
};
use crate::{
    network::packetconn::{OobHandlerTx, PacketConn as RawPacketConn},
    types::Addr,
};
use ed25519_dalek::{PublicKey, SecretKey};
use log::debug;
use std::{cmp::min, error::Error, sync::Arc};

pub struct PacketConnRead {
    pub pconn: RawPacketConn,
    network: NetManagerRead,
    pub sessions: SessionManagerHandle,
}

impl PacketConnRead {
    // The read_from method fulfills the net.PacketConn interface, with a types.Addr returned as the from address.
    // Note that failing to call read_from may cause the connection to block and/or leak memory.
    pub async fn read_from(&mut self, p: &mut [u8]) -> Result<(usize, u8, Addr), String> {
        debug!("++PacketConnRead: read_from");
        if let Some(info) = self.network.read_ch.recv().await {
            let data = info.data;
            let len = min(p.len(), data.len());
            p[..len - 1].copy_from_slice(&data[1..len]);
            debug!("--PacketConnRead: read_from.end OK");
            Ok((len - 1, data[0], info.from.into()))
        } else {
            debug!("--PacketConnRead: read_from.end Err");
            Err("No data recieved.".into())
        }
    }

    pub fn mtu(&self) -> u64 {
        // assuming self.stream.mtu() is a function that returns the MTU of the TcpStream
        self.pconn.mtu() - SESSION_TRAFFIC_OVERHEAD as u64
    }
}

pub struct PacketConn {
    pub secret_ed: EdPriv,
    pub secret_box: BoxPriv,
    pub pconn: RawPacketConn,
    pub network: NetManagerHandle,
    pub sessions: SessionManagerHandle,
}

impl PacketConn {
    pub async fn new(
        secret: &SecretKey,
        oob_handler: Option<OobHandlerTx>,
    ) -> (Arc<Self>, PacketConnRead) {
        let (raw_pconn, raw_pconn_read, dhtree) = RawPacketConn::new(secret, oob_handler);
        let (sessions_handle, sessions_queue) = SessionManager::new();
        let (net_handle, mut net_mgr, net_mgr_read) =
            NetManager::new(raw_pconn_read, sessions_handle.clone());
        let pconn_read = PacketConnRead {
            pconn: raw_pconn.clone(),
            network: net_mgr_read,
            sessions: sessions_handle.clone(),
        };
        let pk: PublicKey = secret.into();
        let mut secret_ed = [0; 64];
        secret_ed[..32].copy_from_slice(&secret.to_bytes()); //;EdPriv::new(secret.to_bytes());
        secret_ed[32..].copy_from_slice(pk.as_bytes());
        let secret_ed = EdPriv::from_slice(&secret_ed).unwrap();
        let secret_box = to_box_priv(&secret_ed);

        let pconn = PacketConn {
            secret_ed,
            secret_box,
            pconn: raw_pconn,
            network: net_handle.clone(),
            sessions: sessions_handle.clone(),
        };
        let pconn = Arc::new(pconn);

        let mut sessions = SessionManager::init(pconn.clone(), sessions_handle, sessions_queue);
        tokio::spawn(async move {
            sessions.handler().await;
        });
        tokio::spawn(async move {
            net_mgr.read().await;
        });

        (pconn, pconn_read)
    }

    pub async fn write_to(&self, p: &[u8], addr: Addr) -> Result<(), Box<dyn Error>> {
        //let dest = addr.into();
        if p.len() as u64 > self.mtu() {
            return Err("oversized message".into());
        }
        self.sessions
            .write_to(EdPub::from_slice(&addr.0 .0).unwrap(), p)
            .await?;
        Ok(())
    }

    pub fn mtu(&self) -> u64 {
        // assuming self.stream.mtu() is a function that returns the MTU of the TcpStream
        self.pconn.mtu() - SESSION_TRAFFIC_OVERHEAD as u64
    }
}
