//! A command's stdin from the host (`exec -i`, `run -i`), and its pty (`-t`). Input frames (proto.rs `IN_*`)
//! number every byte, so a client that reattaches (a pause, a checkpoint, an aborted migration reset its
//! connection) resends what it was not told was taken, and nothing is taken twice or skipped. Bytes are
//! written straight to the command's stdin, one frame at a time: a command that does not read holds the
//! client up (its connection's buffers, then its own bounded buffer), never memory here.

use std::collections::VecDeque;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use crate::proto::{IN_DATA, IN_DETACH, IN_EOF, IN_RESIZE, MAX_INPUT, SESSION_DONE};

/// Clients whose offsets are remembered (the app's stdin takes one at a time, newest first).
const STREAMS: usize = 16;

pub(crate) struct Stdin {
    /// Held while writing, so that one feeder writes at a time, in offset order.
    state: Mutex<State>,
    /// The pty's master, for resizes.
    pty: Option<File>,
    /// What the last write left taken, of whichever stream (a session has only stream 0).
    last: AtomicU64,
}

struct State {
    /// None once closed: by EOF, or because the command closed its end (what comes is then dropped).
    fd: Option<File>,
    /// Bytes taken, by client stream.
    streams: VecDeque<(u64, u64)>,
}

/// Why `feed` returned.
#[derive(Debug, PartialEq)]
pub(crate) enum Fed {
    /// The connection closed, or a newer one took over.
    Gone,
    Detach,
    /// SESSION_DONE.
    Done,
}

impl Stdin {
    /// `fd`: the command's stdin (a pipe's end, or the pty's master, `pty`, again).
    pub(crate) fn new(fd: File, pty: Option<File>) -> io::Result<Stdin> {
        nonblocking(&fd)?;
        Ok(Stdin { state: Mutex::new(State { fd: Some(fd), streams: VecDeque::new() }), pty, last: AtomicU64::new(0) })
    }

    pub(crate) fn tty(&self) -> bool {
        self.pty.is_some()
    }

    pub(crate) fn last(&self) -> u64 {
        self.last.load(Ordering::Acquire)
    }

    pub(crate) fn taken(&self, stream: u64) -> u64 {
        self.state.lock().unwrap().streams.iter().find(|(s, _)| *s == stream).map_or(0, |(_, t)| *t)
    }

    /// Writes what of `data` (at `offset`) was not taken yet, while `current()`; returns what is taken.
    fn write(&self, stream: u64, offset: u64, data: &[u8], current: &dyn Fn() -> bool) -> io::Result<u64> {
        let mut st = self.state.lock().unwrap();
        let i = match st.streams.iter().position(|(s, _)| *s == stream) {
            Some(i) => i,
            None => {
                st.streams.truncate(STREAMS - 1);
                st.streams.push_front((stream, 0));
                0
            }
        };
        let mut taken = st.streams[i].1;
        if offset > taken {
            return Err(io::Error::other(format!("stdin from byte {offset}, but only {taken} were taken")));
        }
        let mut rest = data.get((taken - offset) as usize..).unwrap_or_default();
        while !rest.is_empty() && current() {
            let n = match st.fd.as_mut().map(|f| f.write(rest)) {
                // Closed: what comes is dropped, as a pipe's reader that left would lose it.
                None => rest.len(),
                Some(Ok(n)) => n,
                Some(Err(e)) if e.kind() == io::ErrorKind::WouldBlock => {
                    let mut p = libc::pollfd { fd: st.fd.as_ref().map_or(-1, |f| f.as_raw_fd()), events: libc::POLLOUT, revents: 0 };
                    unsafe { libc::poll(&mut p, 1, 1000) };
                    continue;
                }
                Some(Err(e)) if e.kind() == io::ErrorKind::Interrupted => continue,
                Some(Err(_)) => {
                    st.fd = None;
                    continue;
                }
            };
            rest = &rest[n..];
            taken += n as u64;
            st.streams[i].1 = taken;
            self.last.store(taken, Ordering::Release);
        }
        Ok(taken)
    }

    /// EOF at `offset`: once all before it is taken, a pipe is closed. A pty is not: it has no EOF of its own.
    fn eof(&self, stream: u64, offset: u64) {
        let mut st = self.state.lock().unwrap();
        let taken = st.streams.iter().find(|(s, _)| *s == stream).map_or(0, |(_, t)| *t);
        if self.pty.is_none() && offset <= taken {
            st.fd = None;
        }
    }

    fn resize(&self, rows: u16, cols: u16) {
        if let Some(pty) = &self.pty {
            set_size(pty, rows, cols);
        }
    }
}

/// Reads input frames from `conn` into `stdin` as client `stream` until it closes, detaches, sends
/// SESSION_DONE, or `current()` turns false; `taken` is called with the bytes taken after each frame.
pub(crate) fn feed(conn: &mut impl Read, stdin: &Stdin, stream: u64, current: &dyn Fn() -> bool, taken: &mut dyn FnMut(u64)) -> io::Result<Fed> {
    loop {
        let mut kind = [0];
        if conn.read(&mut kind)? == 0 || !current() {
            return Ok(Fed::Gone);
        }
        if kind[0] == SESSION_DONE {
            return Ok(Fed::Done);
        }
        let mut len = [0; 4];
        conn.read_exact(&mut len)?;
        let len = u32::from_le_bytes(len) as usize;
        if len > MAX_INPUT + 8 {
            return Err(io::Error::other(format!("input frame of {len} bytes")));
        }
        let mut body = vec![0; len];
        conn.read_exact(&mut body)?;
        let offset = || body.get(..8).map(|b| u64::from_le_bytes(b.try_into().unwrap())).ok_or_else(|| io::Error::other("short input frame"));
        match kind[0] {
            IN_DATA => taken(stdin.write(stream, offset()?, &body[8..], current)?),
            IN_EOF => stdin.eof(stream, offset()?),
            IN_RESIZE if len == 4 => stdin.resize(u16::from_le_bytes([body[0], body[1]]), u16::from_le_bytes([body[2], body[3]])),
            IN_DETACH => return Ok(Fed::Detach),
            k => return Err(io::Error::other(format!("bad input frame {k}"))),
        }
        if !current() {
            return Ok(Fed::Gone);
        }
    }
}

fn nonblocking(f: &File) -> io::Result<()> {
    let flags = crate::os(unsafe { libc::fcntl(f.as_raw_fd(), libc::F_GETFL) })?;
    crate::os(unsafe { libc::fcntl(f.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) }).map(drop)
}

fn set_size(pty: &File, rows: u16, cols: u16) {
    let ws = libc::winsize { ws_row: rows, ws_col: cols, ws_xpixel: 0, ws_ypixel: 0 };
    unsafe { libc::ioctl(pty.as_raw_fd(), libc::TIOCSWINSZ, &ws) };
}

/// A new pty: its master and its slave (both close-on-exec), sized `size` (rows, columns), else 24x80.
pub(crate) fn openpty(size: Option<(u16, u16)>) -> io::Result<(File, File)> {
    let flags = libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC;
    let master = unsafe { File::from_raw_fd(crate::os(libc::open(c"/dev/ptmx".as_ptr(), flags))?) };
    let unlock: libc::c_int = 0;
    crate::os(unsafe { libc::ioctl(master.as_raw_fd(), libc::TIOCSPTLCK, &unlock) })?;
    let slave = unsafe { File::from_raw_fd(crate::os(libc::ioctl(master.as_raw_fd(), libc::TIOCGPTPEER, flags))?) };
    let (rows, cols) = size.unwrap_or((24, 80));
    set_size(&master, rows, cols);
    Ok((master, slave))
}

/// The child's stdio: the pty's slave (`controlling_terminal`), else pipes, its stdin one if `stdin` (else none).
pub(crate) fn stdio(cmd: &mut Command, slave: Option<&File>, stdin: bool) -> io::Result<()> {
    match slave {
        Some(slave) => controlling_terminal(cmd, slave),
        None => {
            cmd.stdin(if stdin { Stdio::piped() } else { Stdio::null() }).stdout(Stdio::piped()).stderr(Stdio::piped());
            Ok(())
        }
    }
}

/// Output pipes (or a pty's master), by frame kind.
pub(crate) type Streams = Vec<(File, u8)>;

/// What a child spawned with `stdio` gives: its output streams, by frame kind, and its stdin, from the pty's
/// `master` or its pipes.
pub(crate) fn streams(child: &mut Child, master: Option<File>) -> io::Result<(Streams, Option<Stdin>)> {
    Ok(match master {
        Some(m) => (vec![(m.try_clone()?, crate::FRAME_STDOUT)], Some(Stdin::new(m.try_clone()?, Some(m))?)),
        None => (crate::outputs(child), child.stdin.take().map(|s| Stdin::new(File::from(OwnedFd::from(s)), None)).transpose()?),
    })
}

/// The child's stdio is the pty's slave: it starts a session of its own, with the pty as its terminal.
/// Before any pre_exec that drops root, though a terminal of no other session needs none.
pub(crate) fn controlling_terminal(cmd: &mut Command, slave: &File) -> io::Result<()> {
    cmd.stdin(slave.try_clone()?).stdout(slave.try_clone()?).stderr(slave.try_clone()?);
    unsafe {
        cmd.pre_exec(|| {
            crate::os(libc::setsid())?;
            crate::os(libc::ioctl(0, libc::TIOCSCTTY, 0)).map(drop)
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::frame;

    fn pipe() -> (File, File) {
        let mut fds = [0; 2];
        assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
        unsafe { (File::from_raw_fd(fds[0]), File::from_raw_fd(fds[1])) }
    }

    fn data(offset: u64, bytes: &[u8]) -> Vec<u8> {
        frame(IN_DATA, &[&offset.to_le_bytes(), bytes])
    }

    #[test]
    fn resent_input_is_taken_once_and_gaps_are_refused() {
        let (mut r, w) = pipe();
        let stdin = Stdin::new(w, None).unwrap();
        let mut acks = Vec::new();
        // A reattached client resends from what it was told: overlapping, and wholly old, frames.
        let wire = [data(0, b"hello "), data(3, b"lo world"), data(0, b"hel"), frame(IN_EOF, &[&11u64.to_le_bytes()])].concat();
        assert_eq!(feed(&mut &wire[..], &stdin, 0, &|| true, &mut |t| acks.push(t)).unwrap(), Fed::Gone);
        assert_eq!(acks, [6, 11, 11]);
        let mut got = String::new();
        r.read_to_string(&mut got).unwrap();
        assert_eq!(got, "hello world", "EOF closed the pipe");
        assert!(feed(&mut &data(20, b"x")[..], &stdin, 0, &|| true, &mut |_| ()).is_err(), "a gap");
        // Another client's stream starts at 0; after EOF its bytes are dropped but counted.
        assert_eq!(stdin.taken(7), 0);
        feed(&mut &data(0, b"abc")[..], &stdin, 7, &|| true, &mut |_| ()).unwrap();
        assert_eq!((stdin.taken(7), stdin.taken(0), stdin.last()), (3, 11, 3));
        assert_eq!(feed(&mut &[SESSION_DONE][..], &stdin, 0, &|| true, &mut |_| ()).unwrap(), Fed::Done);
        assert_eq!(feed(&mut &frame(IN_DETACH, &[])[..], &stdin, 0, &|| true, &mut |_| ()).unwrap(), Fed::Detach);
        assert!(feed(&mut &frame(9, &[])[..], &stdin, 0, &|| true, &mut |_| ()).is_err());
    }

    #[test]
    fn a_replaced_feeder_stops_while_blocked() {
        let (_r, w) = pipe();
        let stdin = Stdin::new(w, None).unwrap();
        // More than the pipe holds, never read: the write waits, until the feeder is replaced.
        let big = vec![b'x'; MAX_INPUT];
        let wire: Vec<u8> = (0..8).flat_map(|i| data(i * MAX_INPUT as u64, &big)).collect();
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(1500);
        let current = || std::time::Instant::now() < deadline;
        let mut last = 0;
        assert_eq!(feed(&mut &wire[..], &stdin, 0, &current, &mut |t| last = t).unwrap(), Fed::Gone);
        // However much the pipe holds (a page or two, past a user's pipe limit).
        assert!(last > 0 && last < 8 * MAX_INPUT as u64 && stdin.taken(0) == last && stdin.last() == last, "{last}");
    }

    #[test]
    fn a_pty_child_has_its_terminal_size_and_echo() {
        let (master, slave) = openpty(Some((33, 101))).unwrap();
        let mut cmd = Command::new("/bin/sh");
        cmd.args(["-c", "stty size; read line; echo got:$line"]);
        controlling_terminal(&mut cmd, &slave).unwrap();
        let mut child = cmd.spawn().unwrap();
        drop((cmd, slave));
        let stdin = Stdin::new(master.try_clone().unwrap(), Some(master.try_clone().unwrap())).unwrap();
        feed(&mut &data(0, b"typed\n")[..], &stdin, 0, &|| true, &mut |_| ()).unwrap();
        let mut out = Vec::new();
        let mut buf = [0; 4096];
        // EIO once the child (the slave's only holder) is gone.
        loop {
            let mut p = libc::pollfd { fd: master.as_raw_fd(), events: libc::POLLIN, revents: 0 };
            unsafe { libc::poll(&mut p, 1, 5000) };
            match (&master).read(&mut buf) {
                Ok(n) if n > 0 => out.extend_from_slice(&buf[..n]),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                _ => break,
            }
        }
        assert!(child.wait().unwrap().success());
        let out = String::from_utf8_lossy(&out);
        assert!(out.contains("33 101") && out.contains("typed\r\n") && out.contains("got:typed"), "{out:?}");
    }
}
