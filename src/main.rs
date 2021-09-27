#[macro_use]
extern crate log;

use anyhow::{anyhow, Error, Result};
use byteorder::{BigEndian, ByteOrder};
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::os::unix::net::UnixStream;
use std::process::Command;
use std::str;
use std::sync::atomic;
use std::sync::Arc;
#[cfg(unix)]
use tokio::net::UnixStream as TokioUnixStream;
use which::which;
use wire::{DaemonConnection, Message};

mod passfd;
mod wire;

#[tokio::main]
async fn main() -> Result<()> {
    // Setup the logger. Since we run as a subdaemon we must use
    // Stderr instead of Stdout.
    env_logger::builder()
        .target(env_logger::Target::Stderr)
        .init();
    run().await
}

pub async fn run() -> Result<(), Error> {
    let args: Vec<String> = std::env::args().collect();
    let request_counter = Arc::new(atomic::AtomicUsize::new(0));
    if args.len() == 2 && args[1] == "--version" {
        println!("{}", version());
        return Ok(());
    }

    info!("Starting hsmproxy");
    let node = setup_node_stream()?;
    let remote = RemoteSigner::new();

    process_requests(
        NodeConnection {
            conn: node,
            context: None, // The main connection does not have a context.
        },
        request_counter,
        remote,
    )
        .await;
    Ok(())
}

#[derive(Clone, Debug)]
struct HsmRequest {
    context: Option<HsmRequestContext>,
    raw: Vec<u8>,
    request_id: u32,
}

#[derive(Clone, Debug)]
struct HsmResponse {
    request_id: u32,
    raw: Vec<u8>,
}

#[derive(Clone, Debug)]
struct HsmRequestContext {
    node_id: Vec<u8>,
    dbid: u64,
    capabilities: u64,
}

impl HsmRequestContext {
    pub fn from_client_hsmfd_msg(msg: &Message) -> Result<HsmRequestContext> {
        if msg.msgtype() != 9 {
            return Err(anyhow!("message is not an init"));
        }
        let node_id = &msg.body[2..35];
        let dbid = BigEndian::read_u64(&msg.body[35..43]);
        let capabilities = BigEndian::read_u64(&msg.body[43..51]);
        Ok(HsmRequestContext {
            node_id: node_id.to_vec(),
            dbid,
            capabilities,
        })
    }
}

struct NodeConnection {
    conn: DaemonConnection,
    context: Option<HsmRequestContext>,
}

fn version() -> String {
    let path = which("lightning_hsmd").expect("could not find HSM executable in PATH");

    let version = Command::new(path)
        .args(&["--version"])
        .output()
        .expect("failed to execute process");
    str::from_utf8(&version.stdout).unwrap().trim().to_string()
}

fn setup_node_stream() -> Result<DaemonConnection, Error> {
    let ms = unsafe { UnixStream::from_raw_fd(3) };
    Ok(DaemonConnection::new(TokioUnixStream::from_std(ms)?))
}

fn start_handler(local: NodeConnection, counter: Arc<atomic::AtomicUsize>, remote: RemoteSigner) {
    tokio::spawn(process_requests(local, counter, remote));
}

async fn process_requests(
    node_conn: NodeConnection,
    request_counter: Arc<atomic::AtomicUsize>,
    signer: RemoteSigner,
) {
    let conn = node_conn.conn;
    let context = node_conn.context;
    loop {
        if let Ok(msg) = conn.read().await {
            match msg.msgtype() {
                9 => {
                    // This requests a new client fd with a given context,
                    // handle it locally, and defer the creation of the client
                    // fd on the server side until we need it.
                    let ctx = HsmRequestContext::from_client_hsmfd_msg(&msg).unwrap();
                    debug!("Got a request for a new client fd. Context: {:?}", ctx);

                    let (local, remote) = UnixStream::pair().unwrap();
                    let local = NodeConnection {
                        conn: DaemonConnection::new(TokioUnixStream::from_std(local).unwrap()),
                        context: Some(ctx),
                    };
                    let remote = remote.as_raw_fd();
                    let msg = Message::new_with_fds(vec![0, 109], &vec![remote]);

                    let c = signer.clone();
                    start_handler(local, request_counter.clone(), c);
                    if let Err(e) = conn.write(msg).await {
                        error!("error writing msg to node_connection: {:?}", e);
                        return;
                    }
                }
                _ => {
                    // By default we forward to the remote HSMd
                    let req = HsmRequest {
                        context: context.clone(),
                        raw: msg.body.clone(),
                        request_id: request_counter.fetch_add(1, atomic::Ordering::Relaxed) as u32,
                    };
                    debug!("Got a message from node: {:?}", &req);
                    let res = signer.request(req).await.unwrap();
                    let msg = Message::from_raw(res.raw);
                    debug!("Got respone from hsmd: {:?}", &msg);
                    conn.write(msg).await.unwrap()
                }
            }
        } else {
            error!("Connection lost");
            return;
        }
    }
}

use libhsmd_sys::Hsmd;

/// This struct should be replaced with whatever needs to be done to
/// get the signature request to the remote signer, and return a
/// matching response. Here it just talks to a local instance of
/// `libhsmd`.
#[derive(Clone)]
struct RemoteSigner {
    instance: Hsmd,
    init: Vec<u8>,
}

impl RemoteSigner {
    fn new() -> Self {
        // This secret should eventually be stored on the NFC card
        let secret = [0 as u8; 32];
        let network = "regtest";
        let hsmd = Hsmd::new(secret.to_vec(), network);
        let init = dbg!(hsmd.init()).unwrap();
        Self {
            instance: hsmd,
            init,
        }
    }
}

impl RemoteSigner {
    async fn request(&self, req: HsmRequest) -> Result<HsmResponse> {
        let request_id = req.request_id;
        let response = match req.context {
            None => self.instance.client(1027).handle(req.raw)?,
            Some(ctx) => self
                .instance
                .client_with_context(ctx.capabilities, ctx.dbid, ctx.node_id)
                .handle(req.raw)?,
        };
        Ok(HsmResponse {
            request_id,
            raw: response,
        })
    }
}
