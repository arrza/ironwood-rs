use crate::{
    encrypted::crypto::EdPub,
    network::{crypto::PublicKeyBytes, packetconn::PacketConnRead},
};
use log::debug;
use tokio::sync::mpsc::{self, Receiver, Sender};

use super::session::{SessionInfo, SessionManagerHandle};

const NET_BUFFER_SIZE: usize = 128 * 1024;

#[derive(Debug)]
pub struct NetReadInfo {
    pub from: PublicKeyBytes,
    pub data: Vec<u8>,
}

pub struct NetManager {
    sessions: SessionManagerHandle,
    raw_pc: PacketConnRead,
}

pub struct NetManagerRead {
    pub read_ch: Receiver<NetReadInfo>,
}

#[derive(Clone)]
pub struct NetManagerHandle {
    read_ch_tx: Sender<NetReadInfo>,
}

impl NetManagerHandle {
    pub async fn recv(&self, from: &SessionInfo, data: Vec<u8>) {
        debug!("++recv.");
        self.read_ch_tx
            .send(NetReadInfo {
                from: PublicKeyBytes(from.ed.0),
                data,
            })
            .await
            .unwrap();
        debug!("--recv.");
    }
}

impl NetManager {
    pub fn new(
        pc: PacketConnRead,
        sessions: SessionManagerHandle,
    ) -> (NetManagerHandle, NetManager, NetManagerRead) {
        let (read_ch_tx, read_ch) = mpsc::channel(10);
        (
            NetManagerHandle { read_ch_tx },
            NetManager {
                sessions,
                raw_pc: pc,
            },
            NetManagerRead { read_ch },
        )
    }

    pub async fn read(&mut self) {
        debug!("++NetManager: read");
        let mut buf = vec![0; NET_BUFFER_SIZE];
        loop {
            let (n, from) = self.raw_pc.read_from(&mut buf).await;
            debug!("  NetManager: read ({}, {})", n, from);
            self.sessions
                .handle_data(EdPub::from_slice(&from.0 .0).unwrap(), &buf[..n])
                .await;
        }
        debug!("--NetManager: read");
    }
}
