//! Minimal rtnetlink framing shared by the host and snapshot-resident guest.
use std::io;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicU32, Ordering};

pub struct Netlink(OwnedFd, AtomicU32);

impl Netlink {
    pub fn open() -> io::Result<Self> {
        let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, libc::NETLINK_ROUTE) };
        if fd < 0 { return Err(io::Error::last_os_error()); }
        Ok(Self(unsafe { OwnedFd::from_raw_fd(fd) }, AtomicU32::new(1)))
    }

    // Callers serialize requests so a receiver cannot consume another request's ACK.
    pub fn request(&self, kind: u16, flags: i32, body: &[u8]) -> io::Result<()> {
        let seq = self.1.fetch_add(1, Ordering::Relaxed);
        let msg = message(kind, flags, seq, body);
        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as u16;
        loop {
            let n = unsafe { libc::sendto(self.0.as_raw_fd(), msg.as_ptr().cast(), msg.len(), 0,
                (&addr as *const libc::sockaddr_nl).cast(), std::mem::size_of_val(&addr) as _) };
            if n >= 0 { break; }
            let e = io::Error::last_os_error();
            if e.kind() != io::ErrorKind::Interrupted { return Err(e); }
        }
        let mut ack = [0u8; 1024];
        loop {
            let n = unsafe { libc::recv(self.0.as_raw_fd(), ack.as_mut_ptr().cast(), ack.len(), 0) };
            if n < 0 {
                let e = io::Error::last_os_error();
                if e.kind() != io::ErrorKind::Interrupted { return Err(e); }
            } else if let Some(result) = matching_ack(&ack[..n as usize], seq) {
                return result;
            }
        }
    }
}

fn message(kind: u16, flags: i32, seq: u32, body: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(16 + body.len());
    msg.extend_from_slice(&((16 + body.len()) as u32).to_ne_bytes());
    msg.extend_from_slice(&kind.to_ne_bytes());
    msg.extend_from_slice(&((flags | libc::NLM_F_REQUEST | libc::NLM_F_ACK) as u16).to_ne_bytes());
    msg.extend_from_slice(&seq.to_ne_bytes());
    msg.extend_from_slice(&0u32.to_ne_bytes());
    msg.extend_from_slice(body);
    msg
}

pub fn attr(buf: &mut Vec<u8>, kind: u16, data: &[u8]) {
    buf.extend_from_slice(&((4 + data.len()) as u16).to_ne_bytes());
    buf.extend_from_slice(&kind.to_ne_bytes());
    buf.extend_from_slice(data);
    buf.resize(buf.len().next_multiple_of(4), 0);
}

pub fn address(ifindex: u32, scope: u8, ip: Ipv4Addr) -> Vec<u8> {
    let mut body = vec![libc::AF_INET as u8, 32, 0, scope];
    body.extend_from_slice(&ifindex.to_ne_bytes());
    attr(&mut body, libc::IFA_LOCAL, &ip.octets());
    attr(&mut body, libc::IFA_ADDRESS, &ip.octets());
    body
}

fn matching_ack(mut data: &[u8], seq: u32) -> Option<io::Result<()>> {
    while data.len() >= 16 {
        let len = u32::from_ne_bytes(data[..4].try_into().unwrap()) as usize;
        if len < 16 || len > data.len() {
            return Some(Err(io::Error::new(io::ErrorKind::InvalidData, "malformed netlink ACK")));
        }
        if u32::from_ne_bytes(data[8..12].try_into().unwrap()) == seq
            && u16::from_ne_bytes(data[4..6].try_into().unwrap()) == libc::NLMSG_ERROR as u16
        {
            if len < 20 {
                return Some(Err(io::Error::new(io::ErrorKind::InvalidData, "short netlink ACK")));
            }
            let code = i32::from_ne_bytes(data[16..20].try_into().unwrap());
            return Some(if code == 0 { Ok(()) } else { Err(io::Error::from_raw_os_error(code.saturating_neg())) });
        }
        let aligned = (len + 3) & !3;
        data = data.get(aligned..).unwrap_or_default();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_message_and_attribute_padding() {
        let body = address(7, libc::RT_SCOPE_UNIVERSE, Ipv4Addr::new(10, 0, 0, 2));
        let msg = message(libc::RTM_NEWADDR, libc::NLM_F_CREATE | libc::NLM_F_REPLACE, 42, &body);
        assert_eq!(msg.len(), 40);
        assert_eq!(&msg[..4], &40u32.to_ne_bytes());
        assert_eq!(&msg[4..6], &libc::RTM_NEWADDR.to_ne_bytes());
        assert_eq!(&msg[6..8], &((libc::NLM_F_REQUEST | libc::NLM_F_ACK | libc::NLM_F_CREATE | libc::NLM_F_REPLACE) as u16).to_ne_bytes());
        assert_eq!(&msg[8..16], &[42u32.to_ne_bytes(), 0u32.to_ne_bytes()].concat());
        assert_eq!(&msg[16..24], &[vec![libc::AF_INET as u8, 32, 0, 0], 7u32.to_ne_bytes().to_vec()].concat());
        for (a, kind) in msg[24..].chunks_exact(8).zip([libc::IFA_LOCAL, libc::IFA_ADDRESS]) {
            assert_eq!(a, &[8u16.to_ne_bytes().to_vec(), kind.to_ne_bytes().to_vec(), vec![10, 0, 0, 2]].concat());
        }
        let mut buf = Vec::new();
        attr(&mut buf, libc::IFLA_ADDRESS, &[6; 6]);
        assert_eq!(buf.len(), 12);
        assert_eq!(&buf[..2], &10u16.to_ne_bytes());
        assert_eq!(&buf[10..], &[0, 0]);
    }

    fn ack(seq: u32, code: i32) -> Vec<u8> {
        let mut data = vec![0; 20];
        data[..4].copy_from_slice(&20u32.to_ne_bytes());
        data[4..6].copy_from_slice(&(libc::NLMSG_ERROR as u16).to_ne_bytes());
        data[8..12].copy_from_slice(&seq.to_ne_bytes());
        data[16..20].copy_from_slice(&code.to_ne_bytes());
        data
    }

    #[test]
    fn ack_matches_sequence_and_reports_errors() {
        assert!(matching_ack(&ack(1, -libc::EPERM), 2).is_none());
        let data = [ack(1, -libc::EPERM), ack(2, 0)].concat();
        matching_ack(&data, 2).unwrap().unwrap();
        assert_eq!(matching_ack(&ack(2, -libc::EPERM), 2).unwrap().unwrap_err().raw_os_error(), Some(libc::EPERM));
        let mut short = ack(2, 0);
        short[..4].copy_from_slice(&16u32.to_ne_bytes());
        assert!(matching_ack(&short[..16], 2).unwrap().is_err());
    }
}
