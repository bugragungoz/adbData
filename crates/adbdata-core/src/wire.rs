//! adb's host protocol: what adb's command line itself sends to its server on port 5037.
//!
//! A request is four hexadecimal digits giving its length, then the text. The server answers
//! `OKAY`, or `FAIL` with a message in the same length-prefixed form. `host:transport:<serial>`
//! switches the connection to that phone; what follows (`sync:`, `shell:`) is the phone's.

use crate::devices::{parse_devices, DeviceEntry};
use crate::sync::Sync;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

/// The port adb's server listens on unless `ANDROID_ADB_SERVER_PORT` says otherwise.
pub const DEFAULT_PORT: u16 = 5037;

/// Requests longer than this are refused by the server.
const MAX_REQUEST: usize = 0xffff;

#[derive(Debug, thiserror::Error)]
pub enum WireError {
    /// The server is not running or the connection broke.
    #[error("{0}")]
    Io(#[from] io::Error),
    /// The server or the phone said no, with its reason ("device 'x' not found").
    #[error("{0}")]
    Refused(String),
    /// An answer that does not follow the protocol.
    #[error("unexpected answer from adb: {0}")]
    Protocol(String),
}

impl WireError {
    /// True when the connection itself failed (the server stopped, the phone was unplugged), as
    /// opposed to a request being refused.
    pub fn is_connection(&self) -> bool {
        matches!(self, WireError::Io(_))
    }
}

/// Where adb's server listens.
#[derive(Debug, Clone, Copy)]
pub struct Server {
    pub addr: SocketAddr,
    /// How long a read may wait. Copying a large file waits on the phone, so this is generous.
    pub timeout: Duration,
}

impl Default for Server {
    fn default() -> Self {
        let port = std::env::var("ANDROID_ADB_SERVER_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(DEFAULT_PORT);
        Server::on_port(port)
    }
}

impl Server {
    pub fn on_port(port: u16) -> Self {
        Server {
            addr: SocketAddr::from(([127, 0, 0, 1], port)),
            timeout: Duration::from_secs(60),
        }
    }

    fn connect(&self) -> Result<TcpStream, WireError> {
        let stream = TcpStream::connect_timeout(&self.addr, Duration::from_secs(5))?;
        stream.set_read_timeout(Some(self.timeout))?;
        stream.set_write_timeout(Some(self.timeout))?;
        // Requests are small and each waits for its answer.
        stream.set_nodelay(true)?;
        Ok(stream)
    }

    /// True when a server answers.
    pub fn is_running(&self) -> bool {
        self.version().is_ok()
    }

    /// The server's protocol version (41 for current platform-tools).
    pub fn version(&self) -> Result<u32, WireError> {
        let text = self.query("host:version")?;
        u32::from_str_radix(text.trim(), 16).map_err(|_| WireError::Protocol(text))
    }

    /// The phones the server sees.
    pub fn devices(&self) -> Result<Vec<DeviceEntry>, WireError> {
        Ok(parse_devices(&self.query("host:devices-l")?))
    }

    /// What the phone's adb supports: `ls_v2` and `stat_v2` mean sizes past 4 GB.
    pub fn features(&self, serial: &str) -> Result<Vec<String>, WireError> {
        let text = self.query(&format!("host-serial:{serial}:features"))?;
        Ok(text
            .trim()
            .split(',')
            .filter(|f| !f.is_empty())
            .map(String::from)
            .collect())
    }

    /// A request answered with one length-prefixed text.
    fn query(&self, request: &str) -> Result<String, WireError> {
        let mut stream = self.connect()?;
        send_request(&mut stream, request)?;
        read_status(&mut stream)?;
        read_text(&mut stream)
    }

    /// A connection switched to the phone.
    fn transport(&self, serial: &str) -> Result<TcpStream, WireError> {
        let mut stream = self.connect()?;
        send_request(&mut stream, &format!("host:transport:{serial}"))?;
        read_status(&mut stream)?;
        Ok(stream)
    }

    /// The phone's file service, for listing and copying.
    pub fn sync(&self, serial: &str) -> Result<Sync<TcpStream>, WireError> {
        // A server too old to answer this speaks the first version of the file service.
        let features = self.features(serial).unwrap_or_default();
        let mut stream = self.transport(serial)?;
        send_request(&mut stream, "sync:")?;
        read_status(&mut stream)?;
        Ok(Sync::new(stream, &features))
    }

    /// Runs a command in the phone's shell and returns what it printed (both streams, as the
    /// first version of the shell service mixes them). The command is given to `sh -c` on the
    /// phone, so quote paths with `remote::quote`.
    pub fn shell(&self, serial: &str, command: &str) -> Result<String, WireError> {
        let mut stream = self.transport(serial)?;
        send_request(&mut stream, &format!("shell:{command}"))?;
        read_status(&mut stream)?;
        let mut out = Vec::new();
        stream.read_to_end(&mut out)?;
        Ok(String::from_utf8_lossy(&out).replace("\r\n", "\n"))
    }
}

pub(crate) fn send_request(stream: &mut impl Write, request: &str) -> Result<(), WireError> {
    if request.len() > MAX_REQUEST {
        return Err(WireError::Refused(format!(
            "request too long ({} bytes)",
            request.len()
        )));
    }
    let mut buf = format!("{:04x}", request.len()).into_bytes();
    buf.extend_from_slice(request.as_bytes());
    stream.write_all(&buf)?;
    Ok(())
}

pub(crate) fn read_status(stream: &mut impl Read) -> Result<(), WireError> {
    let mut status = [0u8; 4];
    stream.read_exact(&mut status)?;
    match &status {
        b"OKAY" => Ok(()),
        b"FAIL" => Err(WireError::Refused(read_text(stream)?)),
        other => Err(WireError::Protocol(String::from_utf8_lossy(other).into_owned())),
    }
}

/// Four hexadecimal digits of length, then that many bytes.
pub(crate) fn read_text(stream: &mut impl Read) -> Result<String, WireError> {
    let mut len = [0u8; 4];
    stream.read_exact(&mut len)?;
    let len = std::str::from_utf8(&len)
        .ok()
        .and_then(|s| usize::from_str_radix(s, 16).ok())
        .ok_or_else(|| WireError::Protocol(String::from_utf8_lossy(&len).into_owned()))?;
    let mut text = vec![0u8; len];
    stream.read_exact(&mut text)?;
    Ok(String::from_utf8_lossy(&text).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_carry_their_length_in_hex() {
        let mut out = Vec::new();
        send_request(&mut out, "host:version").unwrap();
        assert_eq!(out, b"000chost:version");
        assert!(matches!(
            send_request(&mut Vec::new(), &"x".repeat(MAX_REQUEST + 1)),
            Err(WireError::Refused(_))
        ));
    }

    #[test]
    fn reads_okay_fail_and_garbage() {
        assert!(read_status(&mut &b"OKAY"[..]).is_ok());
        match read_status(&mut &b"FAIL0014device 'x' not found"[..]) {
            Err(WireError::Refused(m)) => assert_eq!(m, "device 'x' not found"),
            other => panic!("{other:?}"),
        }
        assert!(matches!(read_status(&mut &b"HTTP"[..]), Err(WireError::Protocol(_))));
        assert!(matches!(read_status(&mut &b"OK"[..]), Err(WireError::Io(_))));
        assert!(matches!(read_text(&mut &b"zz00"[..]), Err(WireError::Protocol(_))));
    }
}
