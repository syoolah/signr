use crate::passfd::SyncFdPassingExt;
use anyhow::{anyhow, Result};
use byteorder::{BigEndian, ByteOrder};
use std::os::unix::io::AsRawFd;
use std::os::unix::io::RawFd;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;
use tokio::sync::Mutex;

/// A simple implementation of the inter-daemon protocol wrapping a
/// UnixStream. Easy to read from and write to.
pub struct DaemonConnection {
    conn: Mutex<UnixStream>,
}

#[derive(Clone, Debug)]
pub struct Message {
    typ: u16,
    pub body: Vec<u8>,
    pub(crate) fds: Vec<RawFd>,
    pos: usize,
}

impl Message {
    pub fn new(raw: Vec<u8>) -> Message {
        Message {
            typ: BigEndian::read_u16(&raw),
            body: raw,
            fds: vec![],
            pos: 2,
        }
    }
    pub fn from_raw(raw: Vec<u8>) -> Message {
        Message::new(raw)
    }

    pub fn msgtype(&self) -> u16 {
        self.typ
    }

    pub fn new_with_fds(raw: Vec<u8>, fds: &[RawFd]) -> Message {
        Message {
            typ: BigEndian::read_u16(&raw),
            body: raw,
            fds: fds.to_vec(),
            pos: 2,
        }
    }
}

impl DaemonConnection {
    pub fn new(connection: UnixStream) -> DaemonConnection {
        DaemonConnection {
            conn: Mutex::new(connection),
        }
    }

    fn count_fds(typ: u16) -> i8 {
        match typ {
            109 => 1,
            _ => 0,
        }
    }

    pub async fn read(&self) -> Result<Message> {
        let mut sock = self.conn.lock().await;
        let msglen = sock.read_u32().await?;
        let mut buf = vec![0 as u8; msglen as usize];
        sock.read_exact(&mut buf).await?;
        if buf.len() < msglen as usize {
            return Err(anyhow!("Short read from client"));
        }

        let typ = BigEndian::read_u16(&buf);
        let mut fds = vec![];

        let numfds = DaemonConnection::count_fds(typ);
        for _ in 0..numfds {
            fds.push(sock.as_raw_fd().recv_fd()?);
        }

        if fds.len() == 0 {
            Ok(Message::new(buf))
        } else {
            Ok(Message::new_with_fds(buf, &fds))
        }
    }

    pub async fn write(&self, msg: Message) -> Result<()> {
        trace!(
            "Sending message {} ({} bytes, {} FDs)",
            msg.typ,
            msg.body.len(),
            msg.fds.len()
        );
        let mut client = self.conn.lock().await;
        client.write_u32(msg.body.len() as u32).await?;
        client.write(&msg.body).await?;

        for fd in msg.fds {
            client.as_raw_fd().send_fd(fd)?;
        }

        Ok(())
    }
}
