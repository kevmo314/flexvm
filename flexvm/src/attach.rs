//! Interactive I/O, the CLI's side: the terminal in raw mode, stdin numbered and resent until the guest has
//! taken it (`Feed`: a reattach after a pause, a checkpoint or an aborted migration neither loses nor repeats a
//! byte), `attach` to a VM's app, and `cp`, a tar streamed through an exec of flexvm-init's own tar tool.
//!
//! A `stop` (suspend) ends the clients, which give up once their VM is gone: an exec's command is then
//! closed by the guest after its client has been away 10 minutes of its running time; the app keeps its
//! stdin, to `attach` to again after `start`. A migration ends them too, saying where the VM went (exec's
//! commands run on there; `attach` to the app there).

use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

#[path = "../../guest/src/tar.rs"]
mod tar;

use crate::bail;
use crate::containers::Exit;
use crate::guest::{
    self, frame, FRAME_ACK, FRAME_LOST, FRAME_MSG, FRAME_NOTE, FRAME_STDERR, FRAME_STDOUT, IN_DATA, IN_DETACH, IN_EOF, IN_RESIZE, MAX_INPUT, SESSION_DONE,
};
use crate::host::Host;
use crate::util::{self, Result};

/// Stdin read ahead of what the guest took, at most: past it stdin waits.
const MAX_UNACKED: usize = 1 << 20;
/// docker's detach keys, Ctrl-P Ctrl-Q.
const DETACH_KEYS: [u8; 2] = [0x10, 0x11];

static SAVED: Mutex<Option<libc::termios>> = Mutex::new(None);

pub fn is_tty(fd: i32) -> bool {
    unsafe { libc::isatty(fd) == 1 }
}

/// Stdin's terminal as `change` made it until dropped (or `restore_terminal`, which a panic's hook calls too).
pub struct Term(());

pub fn term(change: impl FnOnce(&mut libc::termios)) -> Result<Term> {
    let mut t: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(0, &mut t) } != 0 {
        return Err(format!("the terminal: {}", std::io::Error::last_os_error()).into());
    }
    // Held until changed: a signal's `restore_terminal` meanwhile waits, then puts it back.
    let mut saved = SAVED.lock().unwrap_or_else(|e| e.into_inner());
    *saved = Some(t);
    change(&mut t);
    if unsafe { libc::tcsetattr(0, libc::TCSANOW, &t) } != 0 {
        saved.take();
        return Err(format!("the terminal: {}", std::io::Error::last_os_error()).into());
    }
    Ok(Term(()))
}

/// Raw mode: keys, Ctrl-C too, go to the guest.
pub fn raw() -> Result<Term> {
    term(|t| unsafe { libc::cfmakeraw(t) })
}

impl Drop for Term {
    fn drop(&mut self) {
        restore_terminal();
    }
}

/// Puts the terminal back as it was before `term`, however the process ends (a panic's hook calls it too).
pub fn restore_terminal() {
    // Waits for a `term` under way (never long: nothing in it panics), so what it changes is put back too.
    let saved = SAVED.lock().unwrap_or_else(|e| e.into_inner()).take();
    if let Some(t) = saved {
        unsafe { libc::tcsetattr(0, libc::TCSANOW, &t) };
    }
}

/// The terminal's rows and columns.
pub fn size() -> Option<(u16, u16)> {
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    [0, 1, 2].into_iter().find(|&fd| unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &mut ws) } == 0 && ws.ws_row > 0)?;
    Some((ws.ws_row, ws.ws_col))
}

/// Ends the process as if it had not touched the terminal.
fn exit(code: i32) -> ! {
    restore_terminal();
    util::exit(code)
}

/// Stdin on its way to the guest: what it has not taken is kept, and sent again on each new connection.
pub struct Feed {
    st: Mutex<St>,
    cv: Condvar,
    tty: bool,
    /// The terminal's size (`size`, but a test's).
    size: fn() -> Option<(u16, u16)>,
}

#[derive(Default)]
struct St {
    /// Bytes from `acked` on.
    buf: VecDeque<u8>,
    acked: u64,
    eof: bool,
    detached: bool,
    /// Bumped by SIGWINCH.
    resizes: u64,
    /// The `resizes` the writers last looked at, and the size last sent (on any connection): a reconnect sends the
    /// size only if it changed meanwhile, as docker's resizes go only on attaching and on SIGWINCH (#868).
    resizes_seen: Option<u64>,
    size_sent: Option<(u16, u16)>,
    /// The connection the size went on, and where its input was then: the guest has it once an ack past that
    /// came on the same connection (it takes frames in order); until then, the next connection sends it again.
    size_unconfirmed: Option<(u64, u64)>,
    /// The connection being served; an older one's writer stops.
    conn: u64,
    /// SESSION_DONE goes out on this connection, then `done_sent`.
    done: Option<u64>,
    done_sent: bool,
    /// No more is read from the source, which is dropped (`cancel`).
    cancelled: bool,
}

impl Feed {
    /// `src`: stdin (None: none, a pty's size only); `keys`: docker's detach keys detach, calling `on_detach`.
    pub fn start(src: Option<Box<dyn Read + Send>>, tty: bool, keys: bool, on_detach: fn()) -> Result<Arc<Feed>> {
        Feed::start_sized(src, tty, keys, on_detach, size)
    }

    fn start_sized(src: Option<Box<dyn Read + Send>>, tty: bool, keys: bool, on_detach: fn(), size: fn() -> Option<(u16, u16)>) -> Result<Arc<Feed>> {
        // Blocked before its threads start, which inherit that: they go to the waiter its caller sets up
        // (`util::on_signal`), which puts the terminal back, never to a thread that would just end the process.
        util::block_signals(&[libc::SIGINT, libc::SIGTERM, libc::SIGHUP]);
        let feed = Arc::new(Feed { st: Mutex::new(St::default()), cv: Condvar::new(), tty, size });
        if let Some(src) = src {
            let f = feed.clone();
            std::thread::Builder::new().spawn(move || f.read(src, keys, on_detach))?;
        }
        if tty {
            watch_resizes(feed.clone())?;
        }
        Ok(feed)
    }

    fn read(&self, mut src: Box<dyn Read + Send>, keys: bool, on_detach: fn()) {
        let (mut buf, mut held) = (vec![0; 16 * 1024], false);
        loop {
            if self.st.lock().unwrap().cancelled {
                return;
            }
            let n = match src.read(&mut buf) {
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Ok(n) => n,
                Err(_) => 0,
            };
            let (mut out, mut detach) = (Vec::with_capacity(n + 1), false);
            for &b in &buf[..n] {
                if keys && held {
                    held = false;
                    if b == DETACH_KEYS[1] {
                        detach = true;
                        break;
                    }
                    out.push(DETACH_KEYS[0]);
                }
                if keys && b == DETACH_KEYS[0] {
                    held = true;
                    continue;
                }
                out.push(b);
            }
            // A Ctrl-P held at the end goes as it is.
            if n == 0 && held {
                out.push(DETACH_KEYS[0]);
            }
            let mut st = self.cv.wait_while(self.st.lock().unwrap(), |s| s.buf.len() >= MAX_UNACKED && !s.cancelled).unwrap();
            if st.cancelled {
                return;
            }
            st.buf.extend(out);
            (st.eof, st.detached) = (n == 0, detach);
            drop(st);
            self.cv.notify_all();
            if detach {
                on_detach();
            }
            if n == 0 || detach {
                return;
            }
        }
    }

    /// The guest took stdin up to `taken`.
    pub fn ack(&self, taken: u64) {
        let mut st = self.st.lock().unwrap();
        let n = taken.saturating_sub(st.acked).min(st.buf.len() as u64);
        st.buf.drain(..n as usize);
        st.acked += n;
        if st.size_unconfirmed.is_some_and(|(conn, at)| conn == st.conn && taken > at) {
            st.size_unconfirmed = None;
        }
        drop(st);
        self.cv.notify_all();
    }

    /// Nothing more is wanted (the guest is done with stdin, as when it failed): the source is dropped, so
    /// that what writes to it (a pipe) is not left blocked once the guest stopped taking any.
    pub fn cancel(&self) {
        self.st.lock().unwrap().cancelled = true;
        self.cv.notify_all();
    }

    pub fn detached(&self) -> bool {
        self.st.lock().unwrap().detached
    }

    /// Sends on `conn`, from what the guest has taken, until the `Writer` is dropped.
    pub fn serve(self: &Arc<Self>, conn: UnixStream) -> Result<Writer> {
        let gen = {
            let mut st = self.st.lock().unwrap();
            st.conn += 1;
            if st.size_unconfirmed.take().is_some() {
                (st.resizes_seen, st.size_sent) = (None, None);
            }
            st.conn
        };
        self.cv.notify_all();
        let (f, out) = (self.clone(), conn.try_clone()?);
        std::thread::Builder::new().spawn(move || f.write(gen, out))?;
        Ok(Writer { feed: self.clone(), gen, conn })
    }

    fn write(&self, gen: u64, mut conn: UnixStream) {
        let (mut sent, mut eof_sent, mut detach_sent) = (0, false, false);
        loop {
            let (bytes, done) = {
                let mut st = self.st.lock().unwrap();
                loop {
                    if st.conn != gen {
                        return;
                    }
                    if st.done == Some(gen) {
                        break (vec![SESSION_DONE], true);
                    }
                    sent = sent.max(st.acked);
                    let end = st.acked + st.buf.len() as u64;
                    let resize = match self.tty && st.resizes_seen != Some(st.resizes) {
                        true => {
                            st.resizes_seen = Some(st.resizes);
                            (self.size)().filter(|now| st.size_sent != Some(*now))
                        }
                        false => None,
                    };
                    if let Some((rows, cols)) = resize {
                        (st.size_sent, st.size_unconfirmed) = (resize, Some((gen, sent)));
                        break (frame(IN_RESIZE, &[&rows.to_le_bytes(), &cols.to_le_bytes()]), false);
                    } else if sent < end {
                        let from = (sent - st.acked) as usize;
                        let chunk: Vec<u8> = st.buf.range(from..(from + MAX_INPUT).min(st.buf.len())).copied().collect();
                        let f = frame(IN_DATA, &[&sent.to_le_bytes(), &chunk]);
                        sent += chunk.len() as u64;
                        break (f, false);
                    } else if st.eof && !eof_sent {
                        eof_sent = true;
                        break (frame(IN_EOF, &[&end.to_le_bytes()]), false);
                    } else if st.detached && !detach_sent {
                        detach_sent = true;
                        break (frame(IN_DETACH, &[]), false);
                    } else {
                        st = self.cv.wait(st).unwrap();
                    }
                }
            };
            let wrote = conn.write_all(&bytes).is_ok();
            if done {
                self.st.lock().unwrap().done_sent = true;
                self.cv.notify_all();
            }
            if !wrote || done {
                return;
            }
        }
    }

    /// After the exit: SESSION_DONE on `w`'s connection, after what was being sent; waits a moment for it.
    pub fn done(&self, w: &Writer) {
        self.st.lock().unwrap().done = Some(w.gen);
        self.cv.notify_all();
        drop(self.cv.wait_timeout_while(self.st.lock().unwrap(), Duration::from_secs(2), |s| !s.done_sent).unwrap());
    }

    /// Waits until there is something to send (input not yet taken, an EOF, a resize): a client whose connection
    /// was taken over by another attach's, with nothing to send, takes it back only once it has (#868). Whether it waited.
    pub fn wait_unsent(&self) -> bool {
        let unsent = |s: &St| !s.buf.is_empty() || s.eof || s.detached || s.cancelled || (self.tty && s.resizes_seen != Some(s.resizes));
        let st = self.st.lock().unwrap();
        let waited = !unsent(&st);
        drop(self.cv.wait_while(st, |s| !unsent(s)).unwrap());
        waited
    }

    fn resized(&self) {
        self.st.lock().unwrap().resizes += 1;
        self.cv.notify_all();
    }
}

/// A connection a `Feed` sends on; dropped, its writer stops and the connection is shut down.
pub struct Writer {
    feed: Arc<Feed>,
    gen: u64,
    conn: UnixStream,
}

impl Drop for Writer {
    fn drop(&mut self) {
        let mut st = self.feed.st.lock().unwrap();
        if st.conn == self.gen {
            st.conn += 1;
        }
        drop(st);
        self.feed.cv.notify_all();
        let _ = self.conn.shutdown(std::net::Shutdown::Both);
    }
}

static WINCH: AtomicI32 = AtomicI32::new(-1);

extern "C" fn on_winch(_: libc::c_int) {
    let fd = WINCH.load(Ordering::Relaxed);
    if fd >= 0 {
        unsafe { libc::write(fd, [0u8].as_ptr().cast(), 1) };
    }
}

/// SIGWINCH resizes the guest's pty (through a pipe: a handler can do little else).
fn watch_resizes(feed: Arc<Feed>) -> Result<()> {
    let mut fds = [0; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    WINCH.store(fds[1], Ordering::Relaxed);
    let mut act: libc::sigaction = unsafe { std::mem::zeroed() };
    act.sa_sigaction = on_winch as usize;
    act.sa_flags = libc::SA_RESTART;
    unsafe { libc::sigaction(libc::SIGWINCH, &act, std::ptr::null_mut()) };
    let woken = fds[0];
    std::thread::Builder::new().spawn(move || {
        let mut buf = [0u8; 64];
        loop {
            let mut p = libc::pollfd { fd: woken, events: libc::POLLIN, revents: 0 };
            unsafe { libc::poll(&mut p, 1, -1) };
            while unsafe { libc::read(woken, buf.as_mut_ptr().cast(), buf.len()) } > 0 {}
            feed.resized();
        }
    })?;
    Ok(())
}

/// Says so, then ends the process: what was attached runs on.
fn detach_now() {
    restore_terminal();
    let _ = std::io::stderr().write_all(b"\r\nread escape sequence\r\n");
    util::exit(0)
}

/// Detaching an exec waits for its IN_DETACH to reach the guest (`exec`).
pub fn detach_later() {
    restore_terminal();
    let _ = std::io::stderr().write_all(b"\r\nread escape sequence\r\n");
}

/// The VM an `attach` follows: the one its first connection reached (an exec's `Instance`), under the name it
/// has now. One made again under the name since (after a kill) is never sent a request, nor stdin.
#[derive(Clone)]
struct Pinned {
    host: Host,
    name: String,
    pin: Arc<Mutex<Shared>>,
}

impl Pinned {
    fn name(&self) -> String {
        self.pin.lock().unwrap().pin.name(&self.host, &self.name)
    }

    fn alive(&self) -> bool {
        self.host.alive(&self.name())
    }

    fn connect(&self, req: &Value) -> Result<UnixStream> {
        let name = self.name();
        repin(&self.pin, |pin| crate::connect_same(&self.host, &name, req, Instant::now() + Duration::from_secs(5), pin))
    }
}

/// The pin the stdin, signal and output threads share, and which of their connects set it.
#[derive(Default)]
struct Shared {
    pin: crate::Pin,
    /// Connects begun, and the number of the latest begun of those whose pin is kept.
    begun: u64,
    kept: u64,
}

/// `connect` on a copy of the pin (not held locked through it), kept only if it succeeded and no connect
/// begun after it was kept already: one that failed, or reached the process before a resume made another,
/// would otherwise put back the process a newer connect replaced.
fn repin<T>(shared: &Mutex<Shared>, connect: impl FnOnce(&mut crate::Pin) -> Result<T>) -> Result<T> {
    let (mut pin, me) = {
        let mut s = shared.lock().unwrap();
        s.begun += 1;
        (s.pin.clone(), s.begun)
    };
    let c = connect(&mut pin)?;
    let mut s = shared.lock().unwrap();
    if me > s.kept {
        (s.pin, s.kept) = (pin, me);
    }
    Ok(c)
}

fn replaced(e: &util::Error) -> bool {
    e.is::<crate::Replaced>()
}

/// A request to the pinned VM's process: its reply read, then its relay.
fn open(vm: &Pinned, req: &Value) -> Result<BufReader<UnixStream>> {
    let c = vm.connect(req)?;
    c.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut r = BufReader::new(c);
    util::answer(util::recv_json(&mut r)?, "vm", "attach failed")?;
    Ok(r)
}

/// Why attaching to the VM can go on no more, its VM process gone: its app's status if it exited.
fn gone(vm: &Pinned) -> Result<i32> {
    let (host, name) = (&vm.host, &vm.name());
    // Only its own VM's end is told: one made again under the name since may have ended too. Its own is the
    // instance it pinned (a resume's process, after a stop and start, too, though never reached); a record from
    // before the instance was kept is judged by the process last reached.
    let last = crate::containers::exit_record(host, name);
    // None: no end of its own recorded (its exited record, if any, is not taken as its own).
    let ours = {
        let mut s = vm.pin.lock().unwrap();
        let ours = match (&last, s.pin.vm, &s.pin.process) {
            (_, _, None) => Some(true),
            (None, ..) => None,
            (Some(Exit { vm: Some(ran), .. }), Some(pinned), _) => Some(*ran == pinned),
            (Some(e), _, Some(process)) => Some(e.ident == *process),
        };
        // Its status and records are those of the process that ended: the one `attach_to` reports.
        if let (Some(true), Some(e), Some(_)) = (ours, &last, &s.pin.process) {
            s.pin.process = Some(e.ident.clone());
        }
        ours
    };
    if ours == Some(false) {
        bail!("vm {name} was killed and made again since this attached; the vm it attached to is gone");
    }
    if let Ok(to) = std::fs::read_to_string(host.vms(name, "moved")?) {
        bail!("vm {name} moved to {to}; attach to it there");
    }
    if let (Some(true), Ok(rec)) = (ours, crate::app::Exited::read(&host.vms(name, "exited")?)) {
        return Ok(rec.status);
    }
    if host.is_suspended(name) {
        bail!("vm {name} was stopped; flexvm start {name}, then attach again");
    }
    bail!("vm {name} ended")
}

/// Whether the VM ended (its process gone), waiting a moment for one that is ending.
fn ended(vm: &Pinned) -> bool {
    let until = Instant::now() + Duration::from_secs(2);
    while vm.alive() {
        if Instant::now() >= until {
            return false;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    true
}

/// Tries at the stdin request whose connection ends before its reply (`stdin_hello`).
const HELLO_TRIES: u32 = 5;

/// The stdin request's reply (`ok TAKEN TTY` or `closed TTY`), and its connection. One that ends with none is
/// asked again: a guest agent from before #832 shuts down the input of an app that ends before it replied, and
/// once it ended replies `closed` (the client then goes on to the app's status).
fn stdin_hello(mut open: impl FnMut() -> Result<BufReader<UnixStream>>, name: &str) -> Result<(BufReader<UnixStream>, String)> {
    let mut tries = 0;
    loop {
        tries += 1;
        let mut r = open()?;
        match guest::read_frame(&mut r)? {
            Some((FRAME_MSG, m)) => return Ok((r, String::from_utf8_lossy(&m).into_owned())),
            None if tries < HELLO_TRIES => std::thread::sleep(Duration::from_millis(100)),
            other => bail!("vm {name}: unexpected stdin reply {other:?}"),
        }
    }
}

/// The stdin request's reply: its stream's input taken so far, and whether the app has a pty.
#[derive(Debug, PartialEq)]
enum Hello {
    Ok {
        taken: u64,
        tty: bool,
    },
    /// The app's stdin is closed (it ended, or ran without -i).
    Closed {
        tty: bool,
    },
}

fn parse_hello(m: &[u8]) -> Result<Hello> {
    let text = String::from_utf8_lossy(m);
    match text.split_whitespace().collect::<Vec<_>>().as_slice() {
        ["ok", taken, tty] => Ok(Hello::Ok { taken: taken.parse()?, tty: *tty == "1" }),
        ["closed", tty] => Ok(Hello::Closed { tty: *tty == "1" }),
        _ => bail!("{}", guest::refusal(m)),
    }
}

/// A resumed stream must still remember everything this client was told it took (an evicted one is refused by a
/// guest agent since #868; one before then says 0, which is caught here only once one of its acks came). What it
/// says it took is taken: an ack lost with the last connection. False: the app's stdin is closed.
fn stdin_resume(feed: &Feed, hello: &[u8]) -> Result<bool> {
    match parse_hello(hello) {
        Ok(Hello::Ok { taken, .. }) => {
            if taken < feed.st.lock().unwrap().acked {
                bail!("stdin stream is gone from the guest; attach again to send more input");
            }
            feed.ack(taken);
            Ok(true)
        }
        Ok(Hello::Closed { .. }) => Ok(false),
        Err(e) => bail!("stdin stream refused by the guest ({e}); attach again to send more input"),
    }
}

/// The stdin stream is lost (the guest forgot it, or refused it): as docker's attach when its connection is lost,
/// this client ends, the terminal put back, with why; the app runs on.
fn stdin_lost(name: &str, e: &util::Error) -> ! {
    restore_terminal();
    let _ = std::io::stderr().write_all(format!("\r\nflexvm: {name}: {e}\n").as_bytes());
    util::exit(1)
}

/// `attach NAME`, and a foreground `run -i`/`-t` (from 0): the app's output from `from` (None: from now on),
/// and stdin to it if it was run with `-i`, until it exits (its status) or the client detaches.
pub fn attach(host: &Host, name: &str, from: Option<u64>) -> Result<i32> {
    attach_to(host, name, from).map(|(code, _)| code)
}

/// `attach`, and the VM process it last reached and verified (`connect_same`): the one its app's status is
/// from, a resume's or a migration's if one replaced the process first reached. None: it reached none (an
/// app done before the first connection).
pub fn attach_to(host: &Host, name: &str, from: Option<u64>) -> Result<(i32, Option<crate::host::Ident>)> {
    let vm = Pinned { host: host.clone(), name: name.to_string(), pin: Arc::default() };
    let code = attach_pinned(&vm, name, from)?;
    let last = vm.pin.lock().unwrap().pin.process.clone();
    Ok((code, last))
}

fn attach_pinned(vm: &Pinned, name: &str, from: Option<u64>) -> Result<i32> {
    let vm = vm.clone();
    let stream = u64::from_str_radix(&util::random_hex(8)?, 16)?;
    let stdin_req = json!({"op": "stdin", "stream": stream});
    let handshake = stdin_hello(|| open(&vm, &stdin_req), name);
    let (first, hello) = match handshake {
        Ok(h) => h,
        Err(e) if replaced(&e) => return Err(e),
        // A foreground run's fast app (`run -i ... true`) and its VM may be gone before the first connection: its status is
        // its exited record's. (`attach` to a VM that ended before is refused, as docker's is.)
        Err(_) if from == Some(0) && ended(&vm) => return gone(&vm),
        Err(e) => return Err(e),
    };
    let (open_stdin, tty) = match parse_hello(hello.as_bytes()).map_err(|e| format!("vm {name}: {e}"))? {
        Hello::Ok { tty, .. } => (true, tty),
        Hello::Closed { tty } => (false, tty),
    };
    if open_stdin && tty && !is_tty(0) {
        bail!("the input device is not a TTY");
    }
    let signals = [libc::SIGINT, libc::SIGTERM, libc::SIGHUP];
    // Before the terminal goes raw, so that no signal finds it raw and nothing to put it back.
    match tty {
        // Not from the terminal (it is raw), or the pty makes them: they end only this client.
        true => util::on_signal(&signals, |sig| exit(128 + sig)),
        // As docker's --sig-proxy: to the app.
        false => proxy_signals(vm.clone(), signals),
    }
    // Raw, and stdin on, only once the output follow is open: from now on, the guest has fixed where "now" is
    // (#866), else what it echoes or prints first can come before that and be left out.
    let mut term = None;
    let code = follow_output(&vm, from, || {
        term = (open_stdin && tty).then(raw).transpose()?;
        if !open_stdin {
            drop(first);
            return Ok(());
        }
        let feed = Feed::start(Some(Box::new(std::io::stdin())), tty, tty && is_tty(0), detach_now)?;
        let vm = vm.clone();
        std::thread::Builder::new().spawn(move || {
            let mut conn = Some(first);
            loop {
                if let Some(mut r) = conn.take() {
                    let _ = r.get_ref().set_read_timeout(None);
                    let Ok(writer) = r.get_ref().try_clone().map_err(util::Error::from).and_then(|c| feed.serve(c)) else { return };
                    while let Ok(Some((kind, data))) = guest::read_frame(&mut r) {
                        if kind == FRAME_ACK && data.len() == 8 {
                            feed.ack(u64::from_le_bytes(data.try_into().unwrap()));
                        }
                    }
                    drop(writer);
                }
                // Taken over by another attach (or lost, a pause's) with nothing to send, it connects again only
                // once it has something, then at once; with input not yet taken, every 200 ms. Two attaches then
                // take stdin from each other only as each is typed into (#868).
                if !feed.wait_unsent() {
                    std::thread::sleep(Duration::from_millis(200));
                }
                if !vm.alive() {
                    return;
                }
                conn = match open(&vm, &stdin_req) {
                    // Another VM under the name: what this one did not take is never sent to it.
                    Err(e) if replaced(&e) => return,
                    Ok(mut r) => match guest::read_frame(&mut r) {
                        Ok(Some((FRAME_MSG, m))) => match stdin_resume(&feed, &m) {
                            Ok(true) => Some(r),
                            // The app ended: its status follows on the output.
                            Ok(false) => {
                                feed.cancel();
                                return;
                            }
                            // Neither typing nor the detach keys would go anywhere (#868).
                            Err(e) => stdin_lost(&vm.name(), &e),
                        },
                        _ => None,
                    },
                    Err(_) => None,
                };
            }
        })?;
        Ok(())
    });
    drop(term);
    code
}

/// `kill -s` for each of `signals` this process gets, to the app (of the pinned VM only).
fn proxy_signals(vm: Pinned, signals: [i32; 3]) {
    let set = util::block_signals(&signals);
    std::thread::spawn(move || loop {
        match util::wait_signal(&set) {
            libc::SIGHUP => exit(128 + libc::SIGHUP),
            sig => {
                let sent = vm.connect(&json!({"op": "signal", "signal": sig})).and_then(|c| {
                    c.set_read_timeout(Some(Duration::from_secs(10)))?;
                    util::answer(util::recv_json(&mut BufReader::new(c))?, "vm", "refused")
                });
                if let Err(e) = sent {
                    crate::log!("flexvm: {}: {e}", vm.name());
                }
            }
        }
    });
}

/// A follow of the app's output from `offset`. From now on (u64::MAX), it is open once its first frame is in:
/// the guest sends one (where it clamped to, or a keepalive) only after fixing where "now" is.
fn open_output(vm: &Pinned, offset: u64) -> Result<BufReader<UnixStream>> {
    let mut r = open(vm, &json!({"op": "attach", "offset": offset}))?;
    if offset == u64::MAX && r.fill_buf()?.is_empty() {
        bail!("vm {}: its output follow ended at once", vm.name());
    }
    r.get_ref().set_read_timeout(Some(Duration::from_secs(20)))?;
    Ok(r)
}

/// The app's output (FRAME_NOTE, flexvm-init's own lines, is left out) until it exits; `started` runs once
/// its first follow is open.
fn follow_output(vm: &Pinned, from: Option<u64>, started: impl FnOnce() -> Result<()>) -> Result<i32> {
    let mut started = Some(started);
    let mut offset = from.unwrap_or(u64::MAX);
    let (mut stdout, mut stderr) = (std::io::stdout(), std::io::stderr());
    loop {
        let name = &vm.name();
        match open_output(vm, offset) {
            Ok(mut r) => {
                if let Some(start) = started.take() {
                    start()?;
                }
                while let Ok(Some((kind, data))) = guest::read_frame(&mut r) {
                    match kind {
                        FRAME_STDOUT | FRAME_STDERR | FRAME_NOTE => {
                            if kind == FRAME_NOTE && crate::util::verbose() {
                                stderr.write_all(&data).and_then(|()| stderr.flush())?;
                            } else if kind != FRAME_NOTE {
                                let out: &mut dyn Write = if kind == FRAME_STDERR { &mut stderr } else { &mut stdout };
                                out.write_all(&data).and_then(|()| out.flush())?;
                            }
                            offset = offset.wrapping_add(data.len() as u64);
                        }
                        FRAME_LOST if data.len() == 8 => offset = u64::from_le_bytes(data.try_into().unwrap()),
                        FRAME_MSG => {
                            let status = String::from_utf8_lossy(&data);
                            return match crate::app::exit_status(&status) {
                                Some(code) => Ok(code),
                                None if status.starts_with("idle") => Err(format!("vm {name}: its app has not started").into()),
                                None => Err(format!("vm {name}: {}", guest::refusal(&data)).into()),
                            };
                        }
                        _ => {}
                    }
                }
            }
            Err(e) if replaced(&e) => return Err(e),
            Err(_) if !vm.alive() => return gone(vm),
            // Paused, or busy: tried again until it runs.
            Err(_) => {}
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// `cp SRC DST`: one of them `NAME:PATH`, the other a host path, or `-` (a tar on stdin or to stdout).
pub fn cp(host: &Host, src: &str, dst: &str) -> Result<i32> {
    let (from, to) = (vm_path(src)?, vm_path(dst)?);
    let tool = |args: &[&str]| -> Vec<String> { ["/proc/self/exe"].iter().chain(args).map(|s| s.to_string()).collect() };
    // As root, from / (where a relative guest path starts), owning what it writes.
    let cmd = |argv: Vec<String>, stdin: bool| json!({"argv": argv, "user": "0:0", "workdir": "/", "stdin": stdin});
    match (from, to) {
        (Some(_), Some(_)) => bail!("cp copies between the host and a vm, not between vms"),
        (None, None) => bail!("cp needs NAME:PATH on one side"),
        (None, Some((name, path))) => {
            let src_arg = src;
            let (src, made): (Box<dyn Read + Send>, _) = match src {
                "-" => (Box::new(std::io::stdin()), None),
                _ => {
                    std::fs::symlink_metadata(src).map_err(|e| format!("{src}: {e}"))?;
                    let (r, mut w) = std::io::pipe()?;
                    let src = src.to_string();
                    // Failed, its archive ends cut short (no end block), which the guest refuses.
                    (Box::new(r), Some(std::thread::spawn(move || tar::create(&src, &mut w))))
                }
            };
            let mode = if src_arg == "-" { "into" } else { "cp" };
            send(src, made, |feed| crate::exec_with(host, &name, &cmd(tool(&["--flexvm-cp-in", mode, &path]), true), &mut std::io::stdout(), Some(feed)))
        }
        (Some((name, path)), None) => {
            if dst == "-" {
                return crate::exec_with(host, &name, &cmd(tool(&["--flexvm-cp-out", &path]), false), &mut std::io::stdout(), None);
            }
            let (r, mut w) = std::io::pipe()?;
            let dst = dst.to_string();
            // What is written is what was asked for (docker cp's basename(PATH), or PATH/.'s contents), never what the guest names.
            let top = tar::top_of(&path)?;
            let unpacked = std::thread::spawn(move || {
                let mut r = BufReader::new(r);
                let res = tar::extract(&mut r, tar::Dest::Guest(&dst, &top), None);
                // The rest is read all the same, so that the exec writing it ends.
                let _ = std::io::copy(&mut r, &mut std::io::sink());
                res
            });
            let code = crate::exec_with(host, &name, &cmd(tool(&["--flexvm-cp-out", &path]), false), &mut w, None);
            drop(w);
            let unpacked = unpacked.join().map_err(|_| "cp: unpacking panicked")?;
            match code? {
                0 => unpacked.map(|()| 0).map_err(|e| format!("cp: {e}").into()),
                code => Ok(code),
            }
        }
    }
}

/// `cp` into a VM: `src` (an archive `made` writes, or stdin's) fed to `unpack`, an exec of the guest's tar tool, its status.
/// Once it ended, however it ended, the feed stops: the guest failing (and taking no more) never leaves `made` blocked on a full pipe.
fn send(src: Box<dyn Read + Send>, made: Option<std::thread::JoinHandle<std::io::Result<()>>>, unpack: impl FnOnce(Arc<Feed>) -> Result<i32>) -> Result<i32> {
    let feed = Feed::start(Some(src), false, false, || {})?;
    let code = unpack(feed.clone());
    feed.cancel();
    let archived = made.map(|t| t.join());
    let code = code?;
    match archived {
        Some(Err(_)) => bail!("cp: archiving panicked"),
        // A pipe closed by the cancel is the guest's failure, which it told already; any other is the archive's.
        Some(Ok(Err(e))) if code == 0 || e.kind() != std::io::ErrorKind::BrokenPipe => Err(format!("cp: {e}").into()),
        _ => Ok(code),
    }
}

/// `NAME:PATH`, docker's way: a path with a `/` before its first `:` (or starting with `.`) is the host's.
fn vm_path(arg: &str) -> Result<Option<(String, String)>> {
    if arg == "-" || arg.starts_with('/') || arg.starts_with('.') {
        return Ok(None);
    }
    match arg.split_once(':') {
        Some((name, _)) if name.contains('/') => Ok(None),
        Some((name, path)) => {
            crate::host::check_name(name)?;
            if path.is_empty() {
                bail!("{arg}: give a path in the vm");
            }
            Ok(Some((name.to_string(), path.to_string())))
        }
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;

    fn frames(peer: &mut UnixStream, n: usize) -> Vec<(u8, Vec<u8>)> {
        peer.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        (0..n).map(|_| guest::read_frame(peer).unwrap().unwrap()).collect()
    }

    fn data(f: &(u8, Vec<u8>)) -> (u64, Vec<u8>) {
        assert_eq!(f.0, IN_DATA);
        (u64::from_le_bytes(f.1[..8].try_into().unwrap()), f.1[8..].to_vec())
    }

    /// A stdin connect begun before a resume ends after the output thread pinned the new process: that pin stays.
    #[test]
    fn a_stale_failed_connect_never_undoes_a_fresh_pin() {
        fn process(pid: u32) -> crate::host::Ident {
            crate::host::Ident { pid, start: 1, boot: "boot".into(), ns: None }
        }
        // Stale ones failing, and succeeding (they reached the process before the resume).
        for fails in [true, false] {
            let shared = Arc::new(Mutex::new(Shared::default()));
            let (began, began_rx) = std::sync::mpsc::channel();
            let (go, go_rx) = std::sync::mpsc::channel::<()>();
            let stale = std::thread::spawn({
                let shared = shared.clone();
                move || {
                    repin(&shared, |pin| {
                        began.send(()).unwrap();
                        go_rx.recv().unwrap();
                        pin.process = Some(process(1));
                        if fails {
                            return Err("connection refused".into());
                        }
                        Ok(())
                    })
                }
            });
            began_rx.recv().unwrap();
            let fresh = std::thread::spawn({
                let shared = shared.clone();
                move || {
                    repin(&shared, |pin| {
                        pin.process = Some(process(2));
                        Ok(())
                    })
                }
            });
            assert!(fresh.join().unwrap().is_ok());
            go.send(()).unwrap();
            assert_eq!(stale.join().unwrap().is_err(), fails);
            assert_eq!(shared.lock().unwrap().pin.process, Some(process(2)), "stale one failing: {fails}");
        }
        // Alone, a connect's pin is kept.
        let shared = Mutex::new(Shared::default());
        repin(&shared, |pin| {
            pin.process = Some(process(3));
            Ok(())
        })
        .unwrap();
        assert_eq!(shared.lock().unwrap().pin.process, Some(process(3)));
    }

    #[test]
    fn a_forgotten_stdin_stream_is_not_retried() {
        let feed = Feed::start(None, false, false, || ()).unwrap();
        {
            let mut st = feed.st.lock().unwrap();
            (st.acked, st.buf) = (12, b"abcdef".iter().copied().collect());
        }
        assert!(stdin_resume(&feed, b"ok 12 0").unwrap());
        assert!(stdin_resume(&feed, b"ok 15 0").unwrap(), "an ack may have been lost");
        let st = feed.st.lock().unwrap();
        assert_eq!((st.acked, st.buf.iter().copied().collect::<Vec<_>>()), (15, b"def".to_vec()), "what it took is taken");
        drop(st);
        assert!(stdin_resume(&feed, b"ok 0 0").unwrap_err().to_string().contains("stdin stream is gone"));
        assert!(!stdin_resume(&feed, b"closed 0").unwrap());
        assert!(stdin_resume(&feed, b"bad reply").is_err());
        // #868: a guest agent that remembers its evictions refuses one (acknowledged or not).
        let e = stdin_resume(&feed, b"error: stdin stream 7 was forgotten").unwrap_err().to_string();
        assert!(e.contains("refused") && e.contains("forgotten") && e.contains("attach again"), "{e}");
    }

    #[test]
    fn stdin_hellos_parse_once() {
        assert_eq!(parse_hello(b"ok 12 1").unwrap(), Hello::Ok { taken: 12, tty: true });
        assert_eq!(parse_hello(b"ok 0 0").unwrap(), Hello::Ok { taken: 0, tty: false });
        assert_eq!(parse_hello(b"closed 1").unwrap(), Hello::Closed { tty: true });
        for bad in [&b"ok x 1"[..], b"ok 1", b"closed", b"", b"unknown request APPIN"] {
            assert!(parse_hello(bad).is_err(), "{bad:?}");
        }
        assert!(parse_hello(b"unknown request APPIN").unwrap_err().to_string().contains("rebuild the rootfs"));
    }

    static ROWS: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(30);

    /// #868: a reconnect resizes the pty only if the terminal's size changed (two attaches taking stdin from each
    /// other would redraw a full-screen app on each), and a client with nothing to send waits to connect again.
    #[test]
    fn a_reconnect_resizes_only_on_a_change_and_an_idle_client_waits() {
        let feed = Feed::start_sized(None, true, false, || (), || Some((ROWS.load(Ordering::SeqCst), 100))).unwrap();
        let resize = |rows: u16| (IN_RESIZE, [rows.to_le_bytes(), 100u16.to_le_bytes()].concat());
        let (conn, mut peer) = UnixStream::pair().unwrap();
        let w = feed.serve(conn).unwrap();
        assert_eq!(frames(&mut peer, 1), [resize(30)]);
        drop(w);
        // Not known to have reached the guest (no ack after it): sent again on the next connection.
        let (conn, mut peer) = UnixStream::pair().unwrap();
        let w = feed.serve(conn).unwrap();
        assert_eq!(frames(&mut peer, 1), [resize(30)]);
        // Input after it, acknowledged: the guest has both.
        feed.st.lock().unwrap().buf.push_back(b'a');
        feed.cv.notify_all();
        assert_eq!(data(&frames(&mut peer, 1)[0]), (0, b"a".to_vec()));
        feed.ack(1);
        drop(w);
        // Nothing to send: it waits.
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn({
            let feed = feed.clone();
            move || tx.send(feed.wait_unsent()).unwrap()
        });
        assert!(rx.recv_timeout(Duration::from_millis(300)).is_err(), "an idle client connects again");
        // A SIGWINCH is something to send; on the new connection only a size that changed goes.
        feed.resized();
        assert!(rx.recv_timeout(Duration::from_secs(10)).unwrap(), "it waited");
        let (conn, mut peer) = UnixStream::pair().unwrap();
        let w = feed.serve(conn).unwrap();
        peer.set_read_timeout(Some(Duration::from_millis(300))).unwrap();
        assert!(guest::read_frame(&mut peer).is_err(), "resized to the same size");
        ROWS.store(40, Ordering::SeqCst);
        feed.resized();
        assert_eq!(frames(&mut peer, 1), [resize(40)]);
        drop(w);
        // Input not yet taken: no wait.
        feed.st.lock().unwrap().buf.push_back(b'x');
        assert!(!feed.wait_unsent());
        let (conn, mut peer) = UnixStream::pair().unwrap();
        let _w = feed.serve(conn).unwrap();
        let got = frames(&mut peer, 2);
        assert_eq!(got[0], resize(40), "the last resize, unconfirmed, again first");
        assert_eq!(data(&got[1]), (1, b"x".to_vec()));
    }

    #[test]
    fn unacknowledged_stdin_is_sent_again_on_the_next_connection() {
        let feed = Feed::start(Some(Box::new(&b"hello world"[..])), false, false, || ()).unwrap();
        let (conn, mut peer) = UnixStream::pair().unwrap();
        let w = feed.serve(conn).unwrap();
        let got = frames(&mut peer, 2);
        assert_eq!(data(&got[0]), (0, b"hello world".to_vec()));
        assert_eq!(got[1], (IN_EOF, 11u64.to_le_bytes().to_vec()));
        feed.ack(6);
        drop(w);
        // A new connection: from what was taken, and EOF again.
        let (conn, mut peer) = UnixStream::pair().unwrap();
        let w = feed.serve(conn).unwrap();
        let got = frames(&mut peer, 2);
        assert_eq!(data(&got[0]), (6, b"world".to_vec()));
        assert_eq!(got[1].0, IN_EOF);
        feed.done(&w);
        let mut done = [0];
        peer.read_exact(&mut done).unwrap();
        assert_eq!(done[0], SESSION_DONE);
        feed.ack(100);
        assert_eq!(feed.st.lock().unwrap().buf.len(), 0, "an acknowledgement past the end takes only what there is");
    }

    static DETACHED: AtomicBool = AtomicBool::new(false);

    #[test]
    fn detach_keys_end_stdin_and_a_lone_ctrl_p_goes_through() {
        let feed = Feed::start(Some(Box::new(&b"a\x10b\x10\x10\x11never"[..])), false, true, || DETACHED.store(true, Ordering::SeqCst)).unwrap();
        let (conn, mut peer) = UnixStream::pair().unwrap();
        let _w = feed.serve(conn).unwrap();
        let got = frames(&mut peer, 2);
        assert_eq!(data(&got[0]), (0, b"a\x10b\x10".to_vec()));
        assert_eq!(got[1], (IN_DETACH, vec![]));
        crate::test_util::wait_until("detach callback", || DETACHED.load(Ordering::SeqCst) && feed.detached());
    }

    #[test]
    fn cp_into_a_vm_that_fails_does_not_hang() {
        let root = crate::test_util::TempDir::new("cp-fail");
        let big = root.join("big");
        std::fs::write(&big, vec![7u8; 8 * MAX_UNACKED]).unwrap();
        let (r, mut w) = std::io::pipe().unwrap();
        let src = big.to_str().unwrap().to_string();
        let made = std::thread::spawn(move || tar::create(&src, &mut w));
        // The guest's extraction fails at once: it takes nothing, and acknowledges nothing.
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || tx.send(send(Box::new(r), Some(made), |_feed| Ok(1)).map_err(|e| e.to_string())));
        assert_eq!(rx.recv_timeout(Duration::from_secs(20)).expect("cp hung after the guest failed"), Ok(1));
    }

    #[test]
    fn an_archive_that_fails_is_cp_s_error() {
        let (r, w) = std::io::pipe().unwrap();
        drop(w);
        let made = std::thread::spawn(|| Err(std::io::Error::other("unreadable")));
        assert!(send(Box::new(r), Some(made), |_| Ok(1)).unwrap_err().to_string().contains("unreadable"));
    }

    #[test]
    fn attach_to_an_app_that_ended_before_the_handshake_takes_its_status() {
        let root = crate::test_util::TempDir::new("attach-fast");
        let host = Host::open(&root.join("state"), &root.join("run")).unwrap();
        // `run -i ... true`: its VM gone before the first connection, its exited record left.
        let rec = crate::app::Exited::new(0, "t".into(), None, Default::default(), Default::default(), 0);
        crate::host::write_record(&host.vms("fast", "exited").unwrap(), &serde_json::to_vec(&rec).unwrap()).unwrap();
        assert_eq!(attach(&host, "fast", Some(0)).unwrap(), 0);
        let rec = crate::app::Exited::new(3, "t".into(), None, Default::default(), Default::default(), 0);
        crate::host::write_record(&host.vms("fast", "exited").unwrap(), &serde_json::to_vec(&rec).unwrap()).unwrap();
        assert_eq!(attach(&host, "fast", Some(0)).unwrap(), 3);
        // Nothing at all: an error still; and `attach NAME` to a VM that ended before, as docker's.
        assert!(attach(&host, "never", Some(0)).is_err());
        assert!(attach(&host, "fast", None).is_err());
    }

    #[test]
    fn an_attach_never_takes_a_replacements_status_for_its_vms() {
        let root = crate::test_util::TempDir::new("attach-replaced");
        let host = Host::open(&root.join("state"), &root.join("run")).unwrap();
        let ours = crate::host::Ident { pid: 999_999_901, start: 1, boot: crate::host::boot_id().into(), ns: None };
        let vm = Pinned { host: host.clone(), name: "web".into(), pin: Arc::default() };
        vm.pin.lock().unwrap().pin.process = Some(ours.clone());
        let rec = crate::app::Exited::new(0, "t".into(), None, Default::default(), Default::default(), 0);
        crate::host::write_record(&host.vms("web", "exited").unwrap(), &serde_json::to_vec(&rec).unwrap()).unwrap();
        // Killed, then another VM made under the name exited: its records are not this attach's VM's.
        crate::containers::record_exit(&host, "web", &crate::host::Ident { pid: 999_999_902, ..ours.clone() }, 0, false);
        assert!(gone(&vm).unwrap_err().to_string().contains("made again"));
        // Its own end: its status.
        crate::containers::record_exit(&host, "web", &ours, 0, false);
        assert_eq!(gone(&vm).unwrap(), 0);
    }

    /// #1208: judged by the instance it pinned. A resume's process (after a stop and start it never reached)
    /// that ended is its own VM's: its status, and the process `attach_to` reports; another instance's is not.
    #[test]
    fn an_attach_takes_its_resumed_vms_status() {
        let root = crate::test_util::TempDir::new("attach-resumed");
        let host = Host::open(&root.join("state"), &root.join("run")).unwrap();
        let ours = crate::host::Ident { pid: 999_999_901, start: 1, boot: crate::host::boot_id().into(), ns: None };
        let resumed = crate::host::Ident { pid: 999_999_902, ..ours.clone() };
        let ip = "10.0.0.2".parse().unwrap();
        let vm = Pinned { host: host.clone(), name: "web".into(), pin: Arc::default() };
        {
            let mut s = vm.pin.lock().unwrap();
            (s.pin.vm, s.pin.process) = (Some(crate::Instance { ip, gen: 7 }), Some(ours.clone()));
        }
        let rec = crate::app::Exited::new(4, "t".into(), None, Default::default(), Default::default(), 0);
        crate::host::write_record(&host.vms("web", "exited").unwrap(), &serde_json::to_vec(&rec).unwrap()).unwrap();
        // Killed and made again (a new generation), that one exited: not its own.
        crate::containers::record_exit_of(&host, "web", &resumed, Some(crate::Instance { ip, gen: 8 }), 4, true);
        assert!(gone(&vm).unwrap_err().to_string().contains("made again"));
        assert_eq!(vm.pin.lock().unwrap().pin.process, Some(ours.clone()));
        // Its resumed process exited: its status, that process its own.
        crate::containers::record_exit_of(&host, "web", &resumed, Some(crate::Instance { ip, gen: 7 }), 4, true);
        assert_eq!(gone(&vm).unwrap(), 4);
        assert_eq!(vm.pin.lock().unwrap().pin.process, Some(resumed));
        // No end of its own recorded: its exited record is not taken as its own.
        std::fs::remove_file(host.vms("web", "exit").unwrap()).unwrap();
        assert!(gone(&vm).is_err());
    }

    /// #832: the stdin connection of an app that ended at once closed before its reply: asked again, it is
    /// told `closed`, and goes on to the app's status; one that never replies is an error still.
    #[test]
    fn a_stdin_reply_cut_off_by_the_apps_end_is_asked_again() {
        let reply = |m: Option<&str>| {
            let (ours, mut peer) = UnixStream::pair().unwrap();
            if let Some(m) = m {
                peer.write_all(&[FRAME_MSG]).unwrap();
                peer.write_all(&(m.len() as u32).to_le_bytes()).unwrap();
                peer.write_all(m.as_bytes()).unwrap();
            }
            drop(peer);
            Ok(BufReader::new(ours))
        };
        let mut asked = 0;
        let (_, hello) = stdin_hello(
            || {
                asked += 1;
                reply((asked == 2).then_some("closed 0"))
            },
            "fast",
        )
        .unwrap();
        assert_eq!((asked, hello.as_str()), (2, "closed 0"));
        let mut asked = 0;
        let e = stdin_hello(
            || {
                asked += 1;
                reply(None)
            },
            "mute",
        )
        .unwrap_err();
        assert!(e.to_string().contains("unexpected stdin reply None"), "{e}");
        assert_eq!(asked, HELLO_TRIES);
        // A refusal to connect is no reply's: not asked again here.
        let mut asked = 0;
        assert!(stdin_hello(
            || {
                asked += 1;
                Err("refused".into())
            },
            "gone"
        )
        .is_err());
        assert_eq!(asked, 1);
    }

    #[test]
    fn vm_paths_are_docker_cps() {
        assert_eq!(vm_path("web:/etc/x").unwrap(), Some(("web".into(), "/etc/x".into())));
        assert_eq!(vm_path("web:rel").unwrap(), Some(("web".into(), "rel".into())));
        for host in ["-", "/abs:x", "./a:b", "dir/a:b", "plain"] {
            assert_eq!(vm_path(host).unwrap(), None, "{host}");
        }
        assert!(vm_path("web:").is_err());
        assert!(vm_path("bad name:/x").is_err());
    }
}
