use super::{
    crypto::{
        box_open, box_seal, ed_check, get_shared, new_box_keys, to_box, BoxPriv, BoxPub, BoxShared,
        EdPriv, EdPub, EdSig, BOX_OVERHEAD, BOX_PUB_SIZE, ED_SIG_SIZE,
    },
    packetconn::PacketConn,
};
use crate::{
    encrypted::crypto::ed_sign,
    network::crypto::PublicKeyBytes,
    types::{self, Addr},
};
use bytes::{BufMut, BytesMut};
use integer_encoding::{VarInt, VarIntReader};
use log::debug;
use std::{
    collections::HashMap,
    error::Error,
    fmt::{self, Display, Formatter},
    io::Cursor,
    sync::{Arc, Mutex as StdMutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{mpsc, Mutex};

pub const SESSION_TIMEOUT: Duration = Duration::from_secs(60);
pub const SESSION_TRAFFIC_OVERHEAD_MIN: usize = 1 + 1 + 1 + 1 + BOX_OVERHEAD + BOX_PUB_SIZE;
pub const SESSION_TRAFFIC_OVERHEAD: usize = SESSION_TRAFFIC_OVERHEAD_MIN + 9 + 9 + 9;
pub const SESSION_INIT_SIZE: usize =
    1 + BOX_PUB_SIZE + BOX_OVERHEAD + ED_SIG_SIZE + BOX_PUB_SIZE + BOX_PUB_SIZE + 8 + 8;
pub const SESSION_ACK_SIZE: usize = SESSION_INIT_SIZE;

#[derive(Debug)]
enum SessionType {
    Dummy,
    Init,
    Ack,
    Traffic,
}

impl From<u8> for SessionType {
    fn from(item: u8) -> Self {
        match item {
            0 => SessionType::Dummy,
            1 => SessionType::Init,
            2 => SessionType::Ack,
            3 => SessionType::Traffic,
            _ => panic!("Invalid value"),
        }
    }
}

impl From<SessionType> for u8 {
    fn from(val: SessionType) -> Self {
        match val {
            SessionType::Dummy => 0,
            SessionType::Init => 1,
            SessionType::Ack => 2,
            SessionType::Traffic => 3,
        }
    }
}

#[derive(Debug)]
pub enum SessionManagerMessages {
    WriteTo(EdPub, Vec<u8>),
    HandleData(EdPub, Vec<u8>),
}

impl Display for SessionManagerMessages {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            SessionManagerMessages::WriteTo(pub_, msg) => {
                write!(f, "WriteTo({}, {})", hex::encode(pub_.0), msg.len())
            }
            SessionManagerMessages::HandleData(pub_, msg) => {
                write!(f, "HandleData({}, {})", hex::encode(pub_.0), msg.len())
            }
        }
    }
}

#[derive(Clone)]
struct Sessions {
    sessions: Arc<Mutex<HashMap<EdPub, Arc<SessionInfo>>>>,
}

impl Sessions {
    fn new() -> Self {
        Sessions {
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    async fn get(&self, key: &EdPub) -> Option<Arc<SessionInfo>> {
        let mut sessions = self.sessions.lock().await;
        if let Some(info) = sessions.get(key) {
            if info.info.lock().unwrap().timer.elapsed() >= SESSION_TIMEOUT {
                sessions.remove(key);
                None
            } else {
                Some(info.clone())
            }
        } else {
            None
        }
    }

    async fn insert(&self, key: EdPub, info: Arc<SessionInfo>) {
        self.sessions.lock().await.insert(key, info);
    }
}

pub struct SessionManager {
    pub pc: Arc<PacketConn>,
    sessions: Sessions,
    buffers: Arc<Mutex<HashMap<EdPub, Arc<Mutex<SessionBuffer>>>>>,
    queue: mpsc::Receiver<SessionManagerMessages>,
    queue_tx: mpsc::Sender<SessionManagerMessages>,
}

#[derive(Clone)]
pub struct SessionManagerNoQueue {
    pub pc: Arc<PacketConn>,
}

impl SessionManagerNoQueue {
    async fn send_init(&self, dest: EdPub, init: &SessionInit) -> Result<(), Box<dyn Error>> {
        debug!("++SessionManagerNoQueue::send_init");
        let bs = init.encrypt(&self.pc.secret_ed, &dest)?;
        self.pc
            .pconn
            .write_to(&bs, types::Addr(PublicKeyBytes(dest.0)))
            .await?;
        debug!("--SessionManagerNoQueue::send_init");
        Ok(())
    }

    async fn send_ack(&self, dest: EdPub, ack: &SessionAck) -> Result<(), Box<dyn Error>> {
        let bs = ack.encrypt(&self.pc.secret_ed, &dest)?;
        self.pc
            .pconn
            .write_to(&bs, types::Addr(PublicKeyBytes(dest.0)))
            .await?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct SessionManagerHandle {
    sessions: Sessions,
    buffers: Arc<Mutex<HashMap<EdPub, Arc<Mutex<SessionBuffer>>>>>,
    queue: mpsc::Sender<SessionManagerMessages>,
}

pub struct SessionManagerQueue {
    queue: mpsc::Receiver<SessionManagerMessages>,
}

impl SessionManagerHandle {
    pub async fn write_to(
        &self,
        to_key: EdPub,
        msg: &[u8],
    ) -> Result<(), mpsc::error::SendError<SessionManagerMessages>> {
        self.queue
            .send(SessionManagerMessages::WriteTo(to_key, msg.to_vec()))
            .await
    }

    pub async fn handle_data(&mut self, pub_: EdPub, data: &[u8]) {
        self.queue
            .send(SessionManagerMessages::HandleData(pub_, data.to_vec()))
            .await;
    }
}

impl SessionManager {
    pub fn new() -> (SessionManagerHandle, SessionManagerQueue) {
        let (queue_tx, queue_rx) = mpsc::channel(1);
        (
            SessionManagerHandle {
                sessions: Sessions::new(),
                buffers: Arc::new(Mutex::new(HashMap::new())),
                queue: queue_tx,
            },
            SessionManagerQueue { queue: queue_rx },
        )
    }

    pub fn init(
        pc: Arc<PacketConn>,
        handle: SessionManagerHandle,
        queue: SessionManagerQueue,
    ) -> Self {
        SessionManager {
            pc,
            sessions: handle.sessions.clone(),
            buffers: handle.buffers.clone(),
            queue: queue.queue,
            queue_tx: handle.queue,
        }
    }

    pub fn handle(&self) -> SessionManagerHandle {
        SessionManagerHandle {
            sessions: self.sessions.clone(),
            buffers: self.buffers.clone(),
            queue: self.queue_tx.clone(),
        }
    }

    fn no_queue(&self) -> SessionManagerNoQueue {
        SessionManagerNoQueue {
            pc: self.pc.clone(),
        }
    }

    pub async fn handler(&mut self) {
        debug!("++SessionManager: handler");
        while let Some(msg) = self.queue.recv().await {
            debug!("  SessionManager: {}", msg);
            match msg {
                SessionManagerMessages::WriteTo(to_key, msg) => {
                    self.write_to(to_key, &msg).await.unwrap()
                }
                SessionManagerMessages::HandleData(pub_, data) => {
                    self.handle_data(pub_, &data).await
                }
            }
        }
        debug!("--SessionManager: handler.end");
    }

    async fn new_session(
        &self,
        ed: &EdPub,
        recv: BoxPub,
        send: BoxPub,
        seq: u64,
    ) -> Arc<SessionInfo> {
        let info = SessionInfo::new(self.no_queue(), ed, recv, send, seq);

        //        info.reset_timer().await;
        let info = Arc::new(info);
        self.sessions.insert(*ed, info.clone()).await;
        info
    }

    async fn session_for_init(
        &self,
        pub_: &EdPub,
        init: &SessionInit,
    ) -> (Arc<SessionInfo>, Option<Arc<Mutex<SessionBuffer>>>) {
        debug!("++SessionMnanager::session_for_init.");
        let mut info = self.sessions.get(pub_).await;
        let mut buf = self.buffers.lock().await.get(pub_).cloned();

        if info.is_none() {
            debug!("  SessionMnanager::session_for_init.1");
            info = Some(
                self.new_session(pub_, init.current, init.next, init.seq)
                    .await,
            );
            if let Some(buffer) = &mut buf {
                self.buffers.lock().await.remove(pub_);
                if let Some(info_arc) = &info {
                    let buffer = buffer.lock().await;
                    let mut info = info_arc.info.lock().unwrap();
                    info.send_pub = buffer.init.current;
                    info.send_priv = buffer.current_priv.clone();
                    info.next_pub = buffer.init.next;
                    info.next_priv = buffer.next_priv.clone();
                    info.fix_shared(0, 0);
                }
            }
        }
        debug!("--SessionMnanager::session_for_init.");
        (info.unwrap(), buf)
    }

    pub async fn handle_data(&mut self, pub_: EdPub, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        let type_ = data[0].into();
        debug!("  SesstionManager: handle_data({:?})", type_);
        match type_ {
            SessionType::Dummy => {}
            SessionType::Init => match SessionInit::decrypt(&self.pc.secret_box, &pub_, data) {
                Ok(init) => {
                    self.handle_init(&pub_, &init).await;
                }
                Err(e) => debug!("  SesstionManager: error({})", e),
            },
            SessionType::Ack => match SessionInit::decrypt(&self.pc.secret_box, &pub_, data) {
                Ok(init) => {
                    let ack = SessionAck { session_init: init };
                    self.handle_ack(&pub_, &ack).await;
                }
                Err(e) => debug!("  SesstionManager: error({})", e),
            },
            SessionType::Traffic => {
                self.handle_traffic(pub_, data).await;
            }
        }
    }

    async fn handle_init(&mut self, pub_: &EdPub, init: &SessionInit) {
        debug!("++SessionManager::handle_init");
        let (info, buf) = self.session_for_init(pub_, init).await;
        {
            info.handle_init(init).await;
            if let Some(buffer) = buf {
                let buffer = buffer.lock().await;
                if !buffer.data.is_empty() {
                    info.do_send(&buffer.data).await;
                }
            }
        }
        debug!("--SessionManager::handle_init");
    }

    async fn handle_ack(&mut self, pub_: &EdPub, ack: &SessionAck) {
        debug!("++SessionManager::handle_ack");
        let is_old = self.sessions.get(pub_).await.is_some();
        let (info, buf) = self.session_for_init(pub_, &ack.session_init).await;
        {
            if is_old {
                debug!("  SessionManager::handle_ack.1");
                info.handle_ack(ack);
            } else {
                debug!("  SessionManager::handle_ack.2");
                info.handle_init(&ack.session_init).await;
            }
            if let Some(buffer) = buf {
                debug!("  SessionManager::handle_ack.3");
                let buffer = buffer.lock().await;
                if !buffer.data.is_empty() {
                    debug!("  SessionManager::handle_ack.4");
                    info.do_send(&buffer.data).await;
                }
            }
        }
        debug!("--SessionManager::handle_ack");
    }

    async fn handle_traffic(&mut self, pub_: EdPub, msg: &[u8]) {
        debug!("++handle_traffic");
        if let Some(info) = self.sessions.get(&pub_).await {
            debug!("  handle_traffic.1");
            info.do_recv(msg).await;
        } else {
            debug!("  handle_traffic.2");
            let (current_pub, _) = new_box_keys();
            let (next_pub, _) = new_box_keys();
            let init = SessionInit::new(&current_pub, &next_pub, 0);
            self.send_init(pub_, &init).await.unwrap();
        }
        debug!("--handle_traffic");
    }

    async fn send_init(&self, dest: EdPub, init: &SessionInit) -> Result<(), Box<dyn Error>> {
        debug!("++send_init");
        let bs = init.encrypt(&self.pc.secret_ed, &dest)?;
        self.pc
            .pconn
            .write_to(&bs, types::Addr(PublicKeyBytes(dest.0)))
            .await?;
        debug!("--send_init");
        Ok(())
    }

    async fn send_ack(&self, dest: EdPub, ack: &SessionAck) -> Result<(), Box<dyn Error>> {
        let bs = ack.encrypt(&self.pc.secret_ed, &dest)?;
        self.pc
            .pconn
            .write_to(&bs, types::Addr(PublicKeyBytes(dest.0)))
            .await?;
        Ok(())
    }

    async fn buffer_and_init(&self, to_key: EdPub, msg: Vec<u8>) -> Result<(), Box<dyn Error>> {
        debug!("++buffer_and_init");
        let mut buffers = self.buffers.lock().await;
        let buf = buffers.entry(to_key).or_insert_with(|| {
            let (current_pub, current_priv) = new_box_keys();
            let (next_pub, next_priv) = new_box_keys();
            let init = SessionInit::new(&current_pub, &next_pub, 0);
            Arc::new(Mutex::new(SessionBuffer {
                init,
                current_priv,
                next_priv,
                data: Vec::new(),
            }))
        });
        buf.lock().await.data = msg.to_vec();

        self.send_init(to_key, &buf.lock().await.init).await;
        debug!("--buffer_and_init");
        Ok(())
    }

    pub async fn write_to(&self, to_key: EdPub, msg: &[u8]) -> Result<(), Box<dyn Error>> {
        debug!("++write_to");
        let info_arc = self.sessions.get(&to_key).await;
        if let Some(info) = info_arc {
            debug!("  write_to.1");
            info.do_send(msg).await?;
        } else {
            debug!("write_to.2");
            self.buffer_and_init(to_key, msg.to_vec()).await?;
        }
        debug!("--write_to");
        Ok(())
    }
}

struct SessionInfoInternal {
    pub seq: u64, // remote seq

    pub remote_key_seq: u64, // signals rotation of current/next
    pub current: BoxPub,     // send to this, expect to receive from it
    pub next: BoxPub,        // if we receive from this, then rotate it to current
    pub local_key_seq: u64,  // signals rotation of recv/send/next
    pub recv_priv: BoxPriv,
    pub recv_pub: BoxPub,
    pub recv_shared: BoxShared,
    pub recv_nonce: u64,
    pub send_priv: BoxPriv, // becomes recvPriv when we rachet forward
    pub send_pub: BoxPub,   // becomes recvPub
    pub send_shared: BoxShared,
    pub send_nonce: u64,
    pub next_priv: BoxPriv, // becomes sendPriv
    pub next_pub: BoxPub,   // becomes sendPub
    pub timer: Instant,
    pub ack: Option<SessionAck>,
    pub since: Instant,
    pub rotated: Instant, // last time we rotated keys
    pub rx: u64,
    pub tx: u64,
}

impl SessionInfoInternal {
    // happens at session creation or after receiving an init/ack
    pub fn fix_shared(&mut self, recv_nonce: u64, send_nonce: u64) {
        self.recv_shared = get_shared(&self.current, &self.recv_priv);
        self.send_shared = get_shared(&self.current, &self.send_priv);
        self.recv_nonce = recv_nonce;
        self.send_nonce = send_nonce;
    }
}

/***************
 * sessionInfo *
 ***************/
#[derive(Clone)]
pub struct SessionInfo {
    pub mgr: SessionManagerNoQueue,
    pub ed: EdPub, // remote ed key
    info: Arc<StdMutex<SessionInfoInternal>>,
}

impl SessionInfo {
    pub fn new(
        mgr: SessionManagerNoQueue,
        ed: &EdPub,
        current: BoxPub,
        next: BoxPub,
        seq: u64,
    ) -> Self {
        let (recv_pub, recv_priv) = new_box_keys();
        let (send_pub, send_priv) = new_box_keys();
        let (next_pub, next_priv) = new_box_keys();
        let recv_shared = get_shared(&current, &recv_priv);
        let send_shared = get_shared(&current, &send_priv);

        SessionInfo {
            mgr,
            ed: *ed,
            info: Arc::new(StdMutex::new(SessionInfoInternal {
                seq: seq - 1, // so the first update works

                current,
                next,
                recv_pub,
                recv_priv,
                send_pub,
                send_priv,
                next_pub,
                next_priv,

                remote_key_seq: 0,
                local_key_seq: 0,
                recv_shared,
                recv_nonce: 0,
                send_shared,
                send_nonce: 0,
                ack: None,
                timer: Instant::now(),
                since: Instant::now(),
                rotated: Instant::now() - Duration::new(60, 0),
                rx: 0,
                tx: 0,
            })),
        }
    }

    // happens at session creation or after receiving an init/ack
    pub fn _fix_shared(&self, recv_nonce: u64, send_nonce: u64) {
        let mut info = self.info.lock().unwrap();
        info.recv_shared = get_shared(&info.current, &info.recv_priv);
        info.send_shared = get_shared(&info.current, &info.send_priv);
        info.recv_nonce = recv_nonce;
        info.send_nonce = send_nonce;
    }

    pub fn _reset_timer(&self) {
        let mut info = self.info.lock().unwrap();
        info.timer = Instant::now();
    }

    pub async fn handle_init(&self, init: &SessionInit) {
        debug!("++handle_init");
        if init.seq <= self.info.lock().unwrap().seq {
            debug!("--handle_init.1");
            return;
        }
        self._handle_update(init);
        // Send a sessionAck
        self._send_ack().await;
        debug!("--handle_init");
    }

    pub fn handle_ack(&self, ack: &SessionAck) {
        debug!("++handle_ack");
        if ack.session_init.seq <= self.info.lock().unwrap().seq {
            debug!("++handle_ack.1");
            return;
        }
        self._handle_update(&ack.session_init);
        debug!("--handle_ack");
    }

    // return true if everything looks OK and the session was updated
    pub fn _handle_update(&self, init: &SessionInit) {
        debug!("++SessionInfo::_handle_update.");
        {
            let mut info = self.info.lock().unwrap();
            info.current = init.current;
            info.next = init.next;
            info.seq = init.seq;
            info.remote_key_seq = init.key_seq;
            // Advance our keys, since this counts as a response
            info.recv_pub = info.send_pub;
            info.recv_priv = info.send_priv.clone();
            info.send_pub = info.next_pub;
            info.send_priv = info.next_priv.clone();
            let (next_pub, next_priv) = new_box_keys();
            info.next_pub = next_pub;
            info.next_priv = next_priv;
            info.local_key_seq += 1;
            // Don't roll back send_nonce, just to be extra safe
            let send_nonce = info.send_nonce;
            info.fix_shared(0, send_nonce);
        }

        self._reset_timer();
        debug!("--SessionInfo::_handle_update.");
    }

    pub async fn do_send(&self, msg: &[u8]) -> Result<(), Box<dyn Error>> {
        debug!("++do_send");
        let mut bs = BytesMut::with_capacity(SESSION_TRAFFIC_OVERHEAD + msg.len());
        {
            let mut info = self.info.lock().unwrap();
            info.send_nonce += 1; // Advance the nonce before anything else
            if info.send_nonce == 0 {
                // Nonce overflowed, so rotate keys
                info.recv_pub = info.send_pub;
                info.recv_priv = info.send_priv.clone();
                info.send_pub = info.next_pub;
                info.send_priv = info.next_priv.clone();
                let (next_pub, next_priv) = new_box_keys();
                info.next_pub = next_pub;
                info.next_priv = next_priv;
                info.local_key_seq += 1;
                info.fix_shared(0, 0);
            }

            bs.put_u8(SessionType::Traffic.into());
            bs.extend_from_slice(&info.local_key_seq.encode_var_vec());
            bs.extend_from_slice(&info.remote_key_seq.encode_var_vec());
            bs.extend_from_slice(&info.send_nonce.encode_var_vec());
            // We need to include info.next_pub below the layer of encryption
            // That way the remote side knows it's us when we send from it later...
            let mut tmp = BytesMut::new();
            tmp.put_slice(&info.next_pub[..]);
            tmp.put_slice(msg);
            let sealed = box_seal(&tmp, info.send_nonce, &info.send_shared);
            bs.extend_from_slice(&sealed);
        }

        // send
        self.mgr
            .pc
            .pconn
            .write_to(&bs, Addr(PublicKeyBytes(self.ed.0)))
            .await?;
        {
            self.info.lock().unwrap().tx += msg.len() as u64;
        }
        self._reset_timer();
        debug!("--do_send");
        Ok(())
    }

    pub async fn do_recv(&self, msg: &[u8]) {
        debug!("++do_recv");
        if msg.len() < SESSION_TRAFFIC_OVERHEAD_MIN || msg[0] != SessionType::Traffic.into() {
            debug!("--do_recv.1");
            return;
        }

        let org_msg = msg;
        let mut cursor = Cursor::new(&msg[1..]);
        let remote_key_seq = cursor.read_varint::<u64>().unwrap();
        let local_key_seq = cursor.read_varint::<u64>().unwrap();
        let nonce = cursor.read_varint::<u64>().unwrap();
        // debug!(
        //     "Info Value: {}, {}, {}\n",
        //     self.local_key_seq, remote_key_seq, nonce
        // );

        let msg = &msg[1 + cursor.position() as usize..];
        let from_current;
        let from_next;
        let to_recv;
        let to_send;
        let shared_key;
        {
            {
                let info = self.info.lock().unwrap();
                from_current = remote_key_seq == info.remote_key_seq;
                from_next = remote_key_seq == info.remote_key_seq + 1;
                to_recv = local_key_seq + 1 == info.local_key_seq;
                to_send = local_key_seq == info.local_key_seq;
            }
            debug!(
                "Decide Value: {}, {}, {}, {}\n",
                from_current, from_next, to_recv, to_send
            );
            //let mut on_success: Box<dyn FnMut(&mut SessionInfo, BoxPub)> = Box::new(|_, _| {});

            if from_current && to_recv {
                let info = self.info.lock().unwrap();
                if info.recv_nonce >= nonce {
                    debug!("--do_recv.2");
                    return;
                }
                shared_key = info.recv_shared;
                // on_success = Box::new(|info: &mut SessionInfo, key: BoxPub| {
                //     info.recv_nonce = nonce;
                // });
            } else if from_next && to_send {
                let info = self.info.lock().unwrap();
                shared_key = get_shared(&info.next, &info.send_priv);
            // on_success = Box::new(|info: &mut SessionInfo, inner_key: BoxPub| {
            //     info.current = info.next;
            //     info.next = inner_key;
            //     info.remote_key_seq += 1;
            //     info.recv_pub = info.send_pub;
            //     info.recv_priv = info.send_priv;
            //     info.send_pub = info.next_pub;
            //     info.send_priv = info.next_priv;
            //     info.local_key_seq += 1;
            //     let (next_pub, next_priv) = new_box_keys();
            //     info.next_pub = next_pub;
            //     info.next_priv = next_priv;
            //     info._fix_shared(nonce, 0);
            // });
            } else if from_next && to_recv {
                let info = self.info.lock().unwrap();
                shared_key = get_shared(&info.next, &info.recv_priv);
            } else {
                self._send_init().await;
                debug!("--do_recv.3");
                return;
            }
        }
        debug!("doRecv Shared Value: {}, {:?}", nonce, shared_key);
        //let mut unboxed = [0; 65536];
        debug!("Enc Value: {} ,{}\n", msg.len(), org_msg.len());
        let mut unboxed = vec![0u8; msg.len() - BOX_OVERHEAD];
        if box_open(&mut unboxed, msg, nonce, &shared_key).is_ok() {
            debug!("  do_recv.1");
            let key = BoxPub::from_slice(&unboxed[..BOX_PUB_SIZE]).unwrap();
            let msg = &unboxed[BOX_PUB_SIZE..];
            self.mgr.pc.network.recv(self, msg.to_vec()).await;
            {
                let mut info = self.info.lock().unwrap();
                info.rx += msg.len() as u64;

                if
                /*self.rotated.is_zero()
                ||*/
                info.rotated.elapsed() > std::time::Duration::from_secs(60) {
                    //on_success(self, key);
                    if from_current && to_recv {
                        info.recv_nonce = nonce;
                    } else {
                        info.current = info.next;
                        info.next = key;
                        info.remote_key_seq += 1;
                        info.recv_pub = info.send_pub;
                        info.recv_priv = info.send_priv.clone();
                        info.send_pub = info.next_pub;
                        info.send_priv = info.next_priv.clone();
                        info.local_key_seq += 1;
                        let (next_pub, next_priv) = new_box_keys();
                        info.next_pub = next_pub;
                        info.next_priv = next_priv;
                        info.fix_shared(nonce, 0);
                    }
                    info.rotated = Instant::now();
                }
            }
            self._reset_timer();
        } else {
            debug!("  do_recv.2");
            self._send_init().await;
        }
        debug!("--do_recv.");
    }

    async fn _send_init(&self) {
        let init;
        {
            let info = self.info.lock().unwrap();
            init = SessionInit::new(&info.send_pub, &info.next_pub, info.local_key_seq);
        }
        self.mgr.send_init(self.ed, &init).await;
    }

    async fn _send_ack(&self) {
        let init;
        let ack;
        {
            let info = self.info.lock().unwrap();
            init = SessionInit::new(&info.send_pub, &info.next_pub, info.local_key_seq);
            ack = SessionAck { session_init: init };
        }
        self.mgr.send_ack(self.ed, &ack).await;
    }
}

/***************
 * sessionInit *
 ***************/
pub struct SessionInit {
    current: BoxPub,
    next: BoxPub,
    key_seq: u64,
    seq: u64, // timestamp or similar
}

impl SessionInit {
    fn new(current: &BoxPub, next: &BoxPub, key_seq: u64) -> Self {
        Self {
            current: *current,
            next: *next,
            key_seq,
            seq: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }

    fn encrypt(&self, from: &EdPriv, to: &EdPub) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let (from_pub, from_priv) = new_box_keys();
        let to_box = to_box(to);

        let mut sig_bytes = Vec::new();
        sig_bytes.extend_from_slice(&from_pub.0);
        sig_bytes.extend_from_slice(&self.current.0);
        sig_bytes.extend_from_slice(&self.next.0);
        let mut buf = BytesMut::with_capacity(8);
        buf.put_u64(self.key_seq);
        sig_bytes.extend_from_slice(&buf);
        buf.clear();
        buf.put_u64(self.seq);
        sig_bytes.extend_from_slice(&buf);

        let sig = ed_sign(&sig_bytes, from);

        let mut payload = Vec::new();
        payload.extend_from_slice(&sig);
        payload.extend_from_slice(&sig_bytes[BOX_PUB_SIZE..]);

        let shared = get_shared(&to_box, &from_priv);
        //let mut bs = vec![0u8; payload.len() + BOX_OVERHEAD];
        let bs = box_seal(&payload, 0, &shared);

        let mut data = Vec::with_capacity(1 + BOX_PUB_SIZE + bs.len());
        data.push(SessionType::Init.into());
        data.extend_from_slice(&from_pub.0);
        data.extend_from_slice(&bs);
        if data.len() != SESSION_INIT_SIZE {
            panic!("this should never happen")
        }

        Ok(data)
    }

    fn decrypt(priv_key: &BoxPriv, from: &EdPub, data: &[u8]) -> Result<SessionInit, String> {
        debug!("++decrypt");
        if data.len() != SESSION_INIT_SIZE {
            return Err("Invalid packet len".into());
        }

        let mut offset = 1;
        let from_box = BoxPub::from_slice(&data[offset..offset + BOX_PUB_SIZE]).unwrap();
        offset += BOX_PUB_SIZE;

        let bs = &data[offset..];
        let shared: BoxShared = get_shared(&from_box, priv_key);
        //println!("Shared Value: {:?}", shared);

        let mut payload = vec![0u8; bs.len() - BOX_OVERHEAD];
        match box_open(&mut payload, bs, 0, &shared) {
            Ok(_) => {}
            Err(_) => return Err("Invalid packet.".into()),
        }
        debug!("Payload Len: {}", payload.len());

        offset = 0;
        let mut sig: EdSig = [0u8; ED_SIG_SIZE];
        sig.copy_from_slice(&payload[offset..offset + ED_SIG_SIZE]);
        offset += ED_SIG_SIZE;
        let tmp = &payload[offset..];

        let current = BoxPub::from_slice(&payload[offset..offset + BOX_PUB_SIZE]).unwrap();
        offset += BOX_PUB_SIZE;
        let next = BoxPub::from_slice(&payload[offset..offset + BOX_PUB_SIZE]).unwrap();
        offset += BOX_PUB_SIZE;

        let key_seq = u64::from_be_bytes(payload[offset..offset + 8].try_into().unwrap());
        offset += 8;
        let seq = u64::from_be_bytes(payload[offset..offset + 8].try_into().unwrap());

        let mut sig_bytes = Vec::new();
        sig_bytes.extend_from_slice(&from_box.0);
        sig_bytes.extend_from_slice(tmp);

        if ed_check(&sig_bytes, &sig, from) {
            // return Err("Invalid signature".into());
        }
        debug!("--decrypt");
        Ok(SessionInit {
            current,
            next,
            key_seq,
            seq,
        })
    }
}

/**************
 * sessionAck *
 **************/
pub struct SessionAck {
    session_init: SessionInit,
}

impl SessionAck {
    fn encrypt(&self, from: &EdPriv, to: &EdPub) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut data = self.session_init.encrypt(from, to)?;
        data[0] = SessionType::Ack.into();
        Ok(data)
    }
}

/*****************
 * sessionBuffer *
 *****************/
struct SessionBuffer {
    data: Vec<u8>,
    init: SessionInit,
    current_priv: BoxPriv, // pairs with init.recv
    next_priv: BoxPriv,    // pairs with init.send
}
