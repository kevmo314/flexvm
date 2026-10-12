//! Resumable command output. Socket writers never hold the process pumps' lock.
use std::collections::{HashMap, VecDeque};
use std::io::{self, Read, Write};
use std::process::{Command, Stdio};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::{spawn, wait_pid, write_frame, Statuses, FRAME_EXIT, FRAME_MSG, FRAME_STDERR, FRAME_STDOUT};

const CAPACITY: usize = 4 * 1024 * 1024;
const MAX_CHUNKS: usize = 4096;
const RETENTION: Duration = Duration::from_secs(300);
/// How long output keeps waiting for a dropped client (the CLI retries for 30 s).
const GRACE: Duration = Duration::from_secs(30);
pub const FRAME_LOST: u8 = 5;

type Session = Arc<(Mutex<Output>, Condvar)>;
pub type Sessions = Arc<Mutex<HashMap<String, Entry>>>;

pub struct Entry {
    command: Vec<u8>,
    output: Session,
}

struct Chunk {
    kind: u8,
    offset: u64,
    data: Vec<u8>,
}

#[derive(Default)]
struct Output {
    chunks: VecDeque<Chunk>,
    start: u64,
    end: u64,
    exit: Option<(i32, Instant)>,
    closed: bool,
    // While a client is attached, or recently was, output waits for it instead of
    // overwriting what it has not been sent; half the ring is slack for bytes in flight.
    readers: usize,
    sent: u64,
    detached: Option<Instant>,
}

impl Output {
    fn push(&mut self, kind: u8, data: &[u8], capacity: usize) {
        self.chunks.push_back(Chunk { kind, offset: self.end, data: data.to_vec() });
        self.end += data.len() as u64;
        // Bound metadata too, even when a command produces many one-byte reads.
        while self.chunks.len() > MAX_CHUNKS {
            self.chunks.pop_front();
        }
        let keep = self.end.saturating_sub(capacity as u64);
        while let Some(chunk) = self.chunks.front_mut() {
            let end = chunk.offset + chunk.data.len() as u64;
            if end <= keep {
                self.chunks.pop_front();
            } else {
                if chunk.offset < keep {
                    chunk.data.drain(..(keep - chunk.offset) as usize);
                    chunk.offset = keep;
                }
                break;
            }
        }
        self.start = self.chunks.front().map_or(self.end, |c| c.offset);
    }

    fn read(&self, offset: u64) -> Option<(u8, Vec<u8>)> {
        self.chunks.iter().find(|c| c.offset + c.data.len() as u64 > offset).map(|c| {
            let mut data = offset.to_le_bytes().to_vec();
            data.extend_from_slice(&c.data[(offset - c.offset) as usize..]);
            (c.kind, data)
        })
    }
}

pub enum Request<'a> {
    Start { id: &'a str, len: usize },
    Attach { id: &'a str, offset: u64 },
    Close { id: &'a str },
}

pub fn parse(line: &str) -> io::Result<Request<'_>> {
    let parts: Vec<_> = line.split_whitespace().collect();
    let id = parts.get(1).copied().unwrap_or("");
    if id.is_empty() || id.len() > 64 || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
        return Err(io::Error::other("bad session id"));
    }
    match parts.as_slice() {
        ["SESSION", _, len] => {
            let len = len.parse::<usize>().map_err(|_| io::Error::other("bad command length"))?;
            if len > 1024 * 1024 {
                return Err(io::Error::other("command too large"));
            }
            Ok(Request::Start { id, len })
        }
        ["ATTACH", _, offset] => {
            Ok(Request::Attach { id, offset: offset.parse().map_err(|_| io::Error::other("bad offset"))? })
        }
        ["CLOSE", _] => Ok(Request::Close { id }),
        _ => Err(io::Error::other("bad session request")),
    }
}

pub fn cleanup(sessions: &Sessions) {
    sessions
        .lock()
        .unwrap()
        .retain(|_, entry| entry.output.0.lock().unwrap().exit.is_none_or(|(_, at)| at.elapsed() < RETENTION));
}

/// Request errors are reported as a message frame; write errors just end the stream,
/// since a frame may have been cut short and anything after it would corrupt it.
pub fn handle(mut w: impl Write, r: impl Read, line: &str, sessions: &Sessions, statuses: &Statuses) -> io::Result<()> {
    match open(r, line, sessions, statuses) {
        Ok(Some((id, offset, output))) => {
            let result = write_frame(&mut w, FRAME_MSG, id.as_bytes()).and_then(|_| drain(&mut w, &output, offset));
            let mut ring = output.0.lock().unwrap();
            ring.readers -= 1;
            ring.detached = Some(Instant::now());
            drop(ring);
            output.1.notify_all();
            result
        }
        Ok(None) => write_frame(&mut w, FRAME_MSG, b"closed"),
        Err(e) => fail(&mut w, e),
    }
}

fn fail(w: &mut impl Write, e: impl std::fmt::Display) -> io::Result<()> {
    write_frame(w, FRAME_MSG, format!("error: {e}").as_bytes())
}

fn open<'a>(mut r: impl Read, line: &'a str, sessions: &Sessions, statuses: &Statuses) -> io::Result<Option<(&'a str, u64, Session)>> {
    Ok(Some(match parse(line)? {
        Request::Start { id, len } => {
            let mut command = vec![0; len];
            r.read_exact(&mut command)?;
            // Serialize lookup and spawn: retrying a lost creation reply cannot spawn twice.
            let mut map = sessions.lock().unwrap();
            let output = if let Some(entry) = map.get(id) {
                if entry.command != command {
                    return Err(io::Error::other("session id already used for another command"));
                }
                attach(&entry.output, 0)
            } else {
                let command_text = std::str::from_utf8(&command).map_err(io::Error::other)?;
                let mut child = spawn(
                    Command::new("/bin/sh")
                        .args(["-c", command_text])
                        .stdin(Stdio::null())
                        .stdout(Stdio::piped())
                        .stderr(Stdio::piped()),
                    statuses,
                    true,
                )?;
                let pid = child.id() as i32;
                let output = Arc::new((Mutex::new(Output { readers: 1, ..Default::default() }), Condvar::new()));
                map.insert(id.to_string(), Entry { command, output: output.clone() });
                let pumps = [
                    pump(child.stdout.take().unwrap(), output.clone(), FRAME_STDOUT),
                    pump(child.stderr.take().unwrap(), output.clone(), FRAME_STDERR),
                ];
                let completion = output.clone();
                let statuses = statuses.clone();
                thread::spawn(move || {
                    for pump in pumps {
                        let _ = pump.join();
                    }
                    let code = wait_pid(&statuses, pid);
                    completion.0.lock().unwrap().exit = Some((code, Instant::now()));
                    completion.1.notify_all();
                });
                output
            };
            (id, 0, output)
        }
        Request::Attach { id, offset } => {
            let map = sessions.lock().unwrap();
            (id, offset, attach(&map.get(id).ok_or_else(|| io::Error::other("unknown session"))?.output, offset))
        }
        Request::Close { id } => {
            let map = sessions.lock().unwrap();
            let entry = map.get(id).ok_or_else(|| io::Error::other("unknown session"))?;
            let mut output = entry.output.0.lock().unwrap();
            if output.exit.is_none() {
                return Err(io::Error::other("session still running"));
            }
            output.closed = true;
            output.chunks.clear();
            return Ok(None);
        }
    }))
}

fn attach(output: &Session, offset: u64) -> Session {
    let mut ring = output.0.lock().unwrap();
    ring.readers += 1;
    ring.sent = offset;
    output.clone()
}

fn pump(mut r: impl Read + Send + 'static, output: Session, kind: u8) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut buf = [0; 16 * 1024];
        loop {
            let n = match r.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            };
            let mut ring = output.0.lock().unwrap();
            while ring.end.saturating_sub(ring.sent) >= CAPACITY as u64 / 2
                && (ring.readers > 0 || ring.detached.is_some_and(|t| t.elapsed() < GRACE))
            {
                ring = output.1.wait_timeout(ring, Duration::from_secs(1)).unwrap().0;
            }
            ring.push(kind, &buf[..n], CAPACITY);
            drop(ring);
            output.1.notify_all();
        }
    })
}

fn drain(w: &mut impl Write, output: &Session, mut offset: u64) -> io::Result<()> {
    loop {
        let (kind, data) = {
            let ring = output.0.lock().unwrap();
            if ring.closed {
                drop(ring);
                return fail(w, "session closed");
            }
            if offset > ring.end {
                drop(ring);
                return fail(w, "offset past output end");
            }
            if offset < ring.start {
                (FRAME_LOST, ring.start.to_le_bytes().to_vec())
            } else if let Some(frame) = ring.read(offset) {
                frame
            } else if let Some((code, _)) = ring.exit {
                let mut data = offset.to_le_bytes().to_vec();
                data.extend_from_slice(&code.to_le_bytes());
                (FRAME_EXIT, data)
            } else {
                let (guard, timeout) = output.1.wait_timeout(ring, Duration::from_secs(1)).unwrap();
                drop(guard);
                if !timeout.timed_out() {
                    continue;
                }
                (FRAME_MSG, b"waiting".to_vec())
            }
        };
        write_frame(w, kind, &data)?;
        match kind {
            FRAME_STDOUT | FRAME_STDERR => {
                offset += (data.len() - 8) as u64;
                output.0.lock().unwrap().sent = offset;
                output.1.notify_all();
            }
            FRAME_EXIT | FRAME_LOST => return Ok(()),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_offsets_and_overflow() {
        let mut ring = Output::default();
        ring.push(FRAME_STDOUT, b"abc", 5);
        ring.push(FRAME_STDERR, b"defg", 5);
        assert_eq!((ring.start, ring.end), (2, 7));
        assert_eq!(ring.read(2), Some((FRAME_STDOUT, [2u64.to_le_bytes().as_slice(), b"c"].concat())));
        assert_eq!(ring.read(5), Some((FRAME_STDERR, [5u64.to_le_bytes().as_slice(), b"fg"].concat())));
        assert!(ring.read(7).is_none());
        ring.push(FRAME_STDOUT, b"0123456789", 5);
        assert_eq!((ring.start, ring.end), (12, 17));
        assert_eq!(&ring.read(12).unwrap().1[8..], b"56789");
        let mut tiny = Output::default();
        for _ in 0..MAX_CHUNKS + 1 {
            tiny.push(FRAME_STDOUT, b"x", CAPACITY);
        }
        assert_eq!(tiny.chunks.len(), MAX_CHUNKS);
        assert_eq!(tiny.start, 1);
    }

    #[test]
    fn writer_does_not_hold_ring_lock() {
        struct Writer {
            output: Session,
        }
        impl Write for Writer {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                assert!(self.output.0.try_lock().is_ok());
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut ring = Output::default();
        ring.push(FRAME_STDOUT, b"hello", CAPACITY);
        ring.exit = Some((0, Instant::now()));
        let output = Arc::new((Mutex::new(ring), Condvar::new()));
        drain(&mut Writer { output: output.clone() }, &output, 0).unwrap();
    }

    #[test]
    fn lost_creation_reply_does_not_spawn_twice() {
        struct Disconnected;
        impl Write for Disconnected {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::ErrorKind::BrokenPipe.into())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let sessions: Sessions = Arc::new(Mutex::new(HashMap::new()));
        let statuses: Statuses = Arc::new((Mutex::new(HashMap::new()), Condvar::new()));
        let command = b"printf hello; printf err >&2; exit 7";
        let line = format!("SESSION retry {}", command.len());
        assert!(handle(Disconnected, command.as_slice(), &line, &sessions, &statuses).is_err());
        // Simulate PID 1's reaper, without leaving a reaper thread in the test process.
        let pid = *statuses.0.lock().unwrap().keys().next().unwrap();
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        statuses.0.lock().unwrap().insert(pid, Some(libc::WEXITSTATUS(status)));
        statuses.1.notify_all();
        let output = sessions.lock().unwrap()["retry"].output.clone();
        let ring = output.0.lock().unwrap();
        let (ring, timeout) = output.1.wait_timeout_while(ring, Duration::from_secs(2), |r| r.exit.is_none()).unwrap();
        assert!(!timeout.timed_out());
        assert_eq!(ring.end, 8);
        drop(ring);
        let mut wire = Vec::new();
        handle(&mut wire, command.as_slice(), &line, &sessions, &statuses).unwrap();
        assert_eq!(wire[0], FRAME_MSG);
        assert!(statuses.0.lock().unwrap().is_empty(), "retry registered a second process");
        assert_eq!(sessions.lock().unwrap().len(), 1);
        let mut wire = Vec::new();
        handle(&mut wire, &b"false"[..], "SESSION retry 5", &sessions, &statuses).unwrap();
        assert!(wire.ends_with(b"error: session id already used for another command"));
        handle(Vec::new(), io::empty(), "CLOSE retry", &sessions, &statuses).unwrap();
        assert!(output.0.lock().unwrap().chunks.is_empty());
        let mut wire = Vec::new();
        handle(&mut wire, command.as_slice(), &line, &sessions, &statuses).unwrap();
        assert!(wire.ends_with(b"error: session closed"));
        assert!(statuses.0.lock().unwrap().is_empty());
        cleanup(&sessions);
        assert_eq!(sessions.lock().unwrap().len(), 1, "closed ID must remain a tombstone");
        output.0.lock().unwrap().exit = Some((7, Instant::now() - RETENTION - Duration::from_secs(1)));
        cleanup(&sessions);
        assert!(sessions.lock().unwrap().is_empty());
    }

    #[test]
    fn attached_reader_applies_backpressure() {
        let output = Arc::new((Mutex::new(Output { readers: 1, ..Default::default() }), Condvar::new()));
        let pumped = pump(io::repeat(b'x').take(2 * CAPACITY as u64), output.clone(), FRAME_STDOUT);
        let ring = output.0.lock().unwrap();
        let (ring, _) = output.1.wait_timeout_while(ring, Duration::from_secs(2), |r| r.end < CAPACITY as u64 / 2).unwrap();
        drop(ring);
        thread::sleep(Duration::from_millis(50));
        let ring = output.0.lock().unwrap();
        assert_eq!(ring.start, 0, "attached reader's unsent output was overwritten");
        assert!(ring.end < CAPACITY as u64 / 2 + 16 * 1024);
        drop(ring);
        output.0.lock().unwrap().readers = 0;
        output.1.notify_all();
        pumped.join().unwrap();
        assert_eq!(output.0.lock().unwrap().start, CAPACITY as u64);
    }

    #[test]
    fn requests() {
        assert!(matches!(parse("SESSION abc 3\n").unwrap(), Request::Start { id: "abc", len: 3 }));
        assert!(matches!(parse("ATTACH abc 42").unwrap(), Request::Attach { offset: 42, .. }));
        assert!(matches!(parse("CLOSE abc").unwrap(), Request::Close { .. }));
        for bad in [
            "SESSION 3",
            "SESSION abc -1",
            "SESSION abc 1048577",
            "ATTACH abc -1",
            "ATTACH abc 1 extra",
            "CLOSE",
            "CLOSE a/b",
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn loss_and_exit_are_explicit_and_retained() {
        let mut ring = Output::default();
        ring.push(FRAME_STDOUT, b"abcdef", 3);
        ring.exit = Some((7, Instant::now()));
        let output = Arc::new((Mutex::new(ring), Condvar::new()));
        let mut wire = Vec::new();
        drain(&mut wire, &output, 0).unwrap();
        assert_eq!(wire[0], FRAME_LOST);
        assert_eq!(&wire[5..], &3u64.to_le_bytes());
        for _ in 0..2 {
            wire.clear();
            drain(&mut wire, &output, 6).unwrap();
            assert_eq!(wire[0], FRAME_EXIT);
            assert_eq!(&wire[5..13], &6u64.to_le_bytes());
            assert_eq!(&wire[13..], &7i32.to_le_bytes());
        }
        wire.clear();
        drain(&mut wire, &output, 7).unwrap();
        assert!(wire.ends_with(b"error: offset past output end"));
    }
}
