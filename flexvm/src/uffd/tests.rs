use super::event::{bucket, bucket_floor, FETCHED, WAITED};
use super::fetch::*;
use super::pages::CHUNK;
use super::server::capture_preload;
use super::*;
use std::io::{Read, Write};
use std::os::fd::FromRawFd;
use std::os::unix::net::UnixStream;

fn pages(states: &[u8]) -> Pages {
    let mut p = Pages::new(states.len());
    for (i, &s) in states.iter().enumerate() {
        p.fill(i, 1, s);
    }
    p
}

fn states(p: &Pages) -> Vec<u8> {
    (0..p.len()).map(|i| p.get(i)).collect()
}

fn discard(p: &Pages, page: usize) -> bool {
    p.discard(&p.removing(), page)
}

/// A page server's listener on loopback, and a source naming it.
fn listen() -> (std::net::TcpListener, Source) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    (listener, Source { addr, vm: "v".into(), mig: 1, regions: Vec::new() })
}

/// The server's side of a page connection: reads the hello, accepts it, and returns the request reader and the writer.
fn accept_hello(s: std::net::TcpStream) -> (io::BufReader<std::net::TcpStream>, std::net::TcpStream) {
    let mut r = io::BufReader::new(s.try_clone().unwrap());
    let mut w = s;
    let mut hello = String::new();
    io::BufRead::read_line(&mut r, &mut hello).unwrap();
    w.write_all(b"{\"ok\": true}\n").unwrap();
    (r, w)
}

/// A page request: `(offset, len)`.
fn request(q: &[u8; 12]) -> (u64, u32) {
    (u64::from_le_bytes(q[..8].try_into().unwrap()), u32::from_le_bytes(q[8..].try_into().unwrap()))
}

#[test]
fn received_fd_is_cloexec() {
    let (a, b) = UnixStream::pair().unwrap();
    let mut pipe = [-1; 2];
    assert_eq!(unsafe { libc::pipe(pipe.as_mut_ptr()) }, 0);
    let [read, _write] = pipe.map(|fd| unsafe { OwnedFd::from_raw_fd(fd) });
    assert_eq!(unsafe { libc::fcntl(read.as_raw_fd(), libc::F_GETFD) }, 0);
    crate::util::send_with_fds(&a, b"{}", &[read.as_raw_fd()], Instant::now() + Duration::from_secs(1)).unwrap();
    let (body, fd) = recv_with_fd(b.as_raw_fd()).unwrap();
    assert_eq!(body, b"{}");
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
    assert_ne!(flags, -1);
    assert_ne!(flags & libc::FD_CLOEXEC, 0);
}

#[test]
fn preload_runs_respect_gaps_regions_and_slots() {
    let mappings = [
        Mapping { base_host_virt_addr: 0, offset: 0, size: 514 * PAGE_SIZE },
        Mapping { base_host_virt_addr: 0, offset: (514 * PAGE_SIZE) as u64, size: 4 * PAGE_SIZE },
    ];
    let list = [0, 1, 3, 510, 511, 512, 513, 514, 515];
    assert_eq!(page_runs(&list, &mappings).collect::<Vec<_>>(), [(0, 2), (2, 1), (3, 2), (5, 2), (7, 2)]);
}

/// Page indexes from a migration source, however wild, always make runs of at least one page: the walk ends.
#[test]
fn preload_runs_end_for_any_page() {
    let mappings = [Mapping { base_host_virt_addr: 0, offset: 0, size: 4 * PAGE_SIZE }];
    let list = [2, 3, u64::MAX - 1, u64::MAX];
    assert_eq!(page_runs(&list, &mappings).collect::<Vec<_>>(), [(0, 2), (2, 1), (3, 1)]);
    assert_eq!(page_runs(&[u64::MAX, u64::MAX], &mappings).collect::<Vec<_>>(), [(0, 1), (1, 1)]);
    assert_eq!(page_runs(&[u64::MAX], &[]).collect::<Vec<_>>(), [(0, 1)]);
    let huge = [Mapping { base_host_virt_addr: 0, offset: (usize::MAX - PAGE_SIZE + 1) as u64, size: PAGE_SIZE }];
    let last = (usize::MAX / PAGE_SIZE) as u64;
    assert_eq!(page_runs(&[last - 1, last, u64::MAX], &huge).collect::<Vec<_>>(), [(0, 1), (1, 1), (2, 1)]);
}

/// A migration header's runs and preload list are checked against the memory regions the source named before any use.
#[test]
fn incoming_header_is_checked() {
    let regions = [(0, (8 * PAGE_SIZE) as u64), ((16 * PAGE_SIZE) as u64, (4 * PAGE_SIZE) as u64)];
    let runs: Runs = vec![(0, 4, REMOTE), (4, 2, ZERO), (16, 4, REMOTE)];
    check_incoming(&runs, &[], &regions).unwrap();
    check_incoming(&runs, &[0, 3, 16, 19], &regions).unwrap();
    for (preload, why) in [
        (vec![u64::MAX], "preload page 18446744073709551615 is not a remote page"),
        (vec![0, u64::MAX], "preload page 18446744073709551615 is not a remote page"),
        (vec![20], "preload page 20 is not a remote page"),
        (vec![4], "preload page 4 is not a remote page"),
        (vec![7], "preload page 7 is not a remote page"),
        (vec![3, 0], "out of order"),
        (vec![3, 3], "out of order"),
    ] {
        let e = check_incoming(&runs, &preload, &regions).unwrap_err().to_string();
        assert!(e.contains(why), "{preload:?}: {e}");
    }
    // Runs past guest memory, or that wrap, are refused whatever the preload list.
    for bad in [vec![(u64::MAX, 1, REMOTE)], vec![(u64::MAX - 1, 4, REMOTE)], vec![(6, 4, REMOTE)], vec![(0, u64::MAX, ZERO)]] {
        assert!(check_incoming(&bad, &[], &regions).is_err(), "{bad:?}");
    }
    // Regions that overflow the address space do not panic.
    assert!(check_incoming(&vec![(u64::MAX, 1, REMOTE)], &[u64::MAX], &[(u64::MAX, u64::MAX)]).is_err());
    let r = remote_among(&vec![(u64::MAX - 1, 4, REMOTE)], [u64::MAX - 1, u64::MAX]);
    assert_eq!(r, vec![u64::MAX - 1]);
}

#[test]
fn incoming_preload_is_bounded() {
    let regions = [(0, ((MAX_PRELOAD + 1) * PAGE_SIZE) as u64)];
    let runs = vec![(0, (MAX_PRELOAD + 1) as u64, REMOTE)];
    let mut preload: Vec<u64> = (0..MAX_PRELOAD as u64).collect();
    check_incoming(&runs, &preload, &regions).unwrap();
    preload.push(MAX_PRELOAD as u64);
    let e = check_incoming(&runs, &preload, &regions).unwrap_err().to_string();
    assert!(e.contains(&format!("{} pages to preload, more than {MAX_PRELOAD}", MAX_PRELOAD + 1)), "{e}");
}

#[test]
fn install_runs_past_partial_copies_eexist_and_discards() {
    let p = pages(&[REMOTE; 6]);
    assert_eq!(p.claim(0, 6, REMOTE, |_| true), 6);
    discard(&p, 3);
    let mut calls = Vec::new();
    let (resolved, res) = p.install(0, 6, REMOTE, None, |first, n| {
        calls.push((first, n));
        if first == 0 {
            Ok(1)
        } else if first == 1 {
            Err(os(libc::EEXIST))
        } else {
            Ok(n)
        }
    });
    res.unwrap();
    assert_eq!(calls, [(0, 3), (1, 2), (2, 1), (4, 2)]);
    assert_eq!(resolved, 6);
    assert_eq!(states(&p), [PRESENT, PRESENT, PRESENT, ZERO, PRESENT, PRESENT]);
}

#[test]
fn preload_capture_reads_sparse_runs_across_regions_and_iovec_batches() {
    let source: Vec<u8> = (0..2200).flat_map(|i| vec![(i % 251) as u8; PAGE_SIZE]).collect();
    let mappings = [
        Mapping { base_host_virt_addr: source.as_ptr() as u64, offset: 0, size: 1100 * PAGE_SIZE },
        Mapping { base_host_virt_addr: unsafe { source.as_ptr().add(1100 * PAGE_SIZE) } as u64, offset: (1100 * PAGE_SIZE) as u64, size: 1100 * PAGE_SIZE },
    ];
    let list: Vec<u64> = (0..2200).filter(|p| p % 2 == 0 || (1097..1103).contains(p)).collect();
    let mut data = vec![0; list.len() * PAGE_SIZE];
    let mut batches = Vec::new();
    capture_preload(&mappings, &list, &mut data, |local, remote| {
        batches.push(local.len());
        let mut bytes = 0;
        for (dst, src) in local.iter().zip(remote) {
            assert_eq!(dst.iov_len, src.iov_len);
            unsafe { std::ptr::copy_nonoverlapping(src.iov_base.cast::<u8>(), dst.iov_base.cast::<u8>(), dst.iov_len) };
            bytes += dst.iov_len;
        }
        Ok(bytes)
    })
    .unwrap();
    assert_eq!(batches.len(), 2);
    assert_eq!(batches[0], 1024);
    for (&p, actual) in list.iter().zip(data.chunks_exact(PAGE_SIZE)) {
        assert_eq!(actual, &source[p as usize * PAGE_SIZE..(p as usize + 1) * PAGE_SIZE]);
    }
    assert!(capture_preload(&mappings, &[2200], &mut data[..PAGE_SIZE], |_, _| panic!("invalid offset")).is_err());
    assert!(capture_preload(&mappings, &[0], &mut [], |_, _| panic!("invalid size")).is_err());
    assert!(capture_preload(&mappings, &[0], &mut data[..PAGE_SIZE], |_, _| Ok(PAGE_SIZE - 1)).is_err());
    assert!(capture_preload(&mappings, &[0], &mut data[..PAGE_SIZE], |_, _| Err(os(libc::ESRCH))).is_err());
}

#[test]
fn dirty_count_skips_untouched_chunks() {
    for n in [0, 1, CHUNK, CHUNK * 3 + 1, CHUNK * 65 + 1] {
        let p = Pages::new(n);
        assert_eq!(p.dirty_count(), 0);
        for page in [CHUNK, CHUNK + 63, CHUNK * 2 - 1, n.saturating_sub(1)] {
            if page < n {
                p.mark_dirty(page);
            }
        }
        let full = || p.dirty.iter().map(|w| w.load(Ordering::Relaxed).count_ones() as usize).sum::<usize>();
        let count = full();
        assert_eq!(p.dirty_count(), count);
        assert_eq!(full(), count);
        // Poison untouched chunks without marking them touched: neither scan should read their words.
        for (_, w) in p.dirty.iter().enumerate().filter(|&(i, _)| !p.touched(i * 64)) {
            w.store(u64::MAX, Ordering::Relaxed);
        }
        assert_eq!(p.dirty_count(), count);
        assert_eq!(p.dirty_bits(true).iter().map(|w| w.count_ones() as usize).sum::<usize>(), count);
        assert_eq!(p.dirty_count(), 0);
        if n > CHUNK {
            assert!(full() > 0);
        }
    }
}

#[test]
fn dirty_scan_skips_untouched_chunks_and_keeps_dirty_base_pages() {
    let p = Pages::new(CHUNK * 3 + 1);
    p.mark_dirty(CHUNK + 7);
    p.mark_dirty(CHUNK * 3);
    let bits = p.dirty_bits(true);
    assert_eq!(bits.iter().map(|b| b.count_ones()).sum::<u32>(), 2);
    assert_eq!(p.dirty_bits(false).iter().sum::<u64>(), 0);
    p.restore_dirty(&bits);
    assert_eq!(p.dirty_bits(false), bits);
    assert!(!p.touched(0));
    assert!(!p.touched(CHUNK * 2));
}

/// Streamed installs under random interleavings: the fetch delivers its run in random pieces and may fail part way (and
/// be retried, or not), REMOVEs land while it is on the wire, copies stop part way, hit EEXIST, EAGAIN or fail. Every
/// page ends settled, installed pages get their own contents, and every REMOTE page is counted resolved once.
#[test]
fn streamed_installs_add_up() {
    let seed = AtomicU64::new(0x2545_f491_4f6c_dd1d);
    let rand = |n: usize| {
        let mut s = seed.load(Ordering::Relaxed);
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        seed.store(s, Ordering::Relaxed);
        (s % n as u64) as usize
    };
    let stop = AtomicBool::new(false);
    let mut fetches = 0;
    for _ in 0..1000 {
        let p = pages(&[REMOTE; 64]);
        let mut resolved = 0;
        for _ in 0..20 {
            let first = rand(64);
            if rand(4) == 0 {
                resolved += discard(&p, first) as usize;
                continue;
            }
            let n = p.claim(first, 1 + rand(48), REMOTE, |_| true);
            if n == 0 {
                continue;
            }
            let (fails, retries) = (rand(3), rand(2) == 0);
            let (mut attempts, mut discarded) = (0, 0);
            let mut fetch = |off: u64, buf: &mut [u8], _: &AtomicBool, progress: &mut dyn FnMut(&[u8]) -> bool| -> io::Result<()> {
                attempts += 1;
                let start = off as usize / PAGE_SIZE;
                assert!(start >= first && start + buf.len() / PAGE_SIZE == first + n, "refetches what has yet to arrive");
                let mut filled = 0;
                while filled < buf.len() {
                    let k = (1 + rand(3 * PAGE_SIZE)).min(buf.len() - filled);
                    for (i, b) in buf[filled..filled + k].iter_mut().enumerate() {
                        *b = (start + (filled + i) / PAGE_SIZE) as u8;
                    }
                    filled += k;
                    if rand(8) == 0 {
                        discarded += discard(&p, first + rand(n)) as usize;
                    }
                    if attempts <= fails && rand(4) == 0 {
                        return Err(os(libc::ECONNRESET));
                    }
                    if !progress(&buf[..filled]) {
                        return Err(io::Error::other(FetchFailure::Cancelled));
                    }
                }
                Ok(())
            };
            let mut retry = |_: &io::Error| retries;
            let (r, _) = p.fetch_install(first, n, &mut vec![0u8; n * PAGE_SIZE], &mut fetch, &stop, &mut retry, |pg, c, src| {
                assert!(src.len() >= c * PAGE_SIZE);
                for i in 0..c {
                    assert!(src[i * PAGE_SIZE..(i + 1) * PAGE_SIZE].iter().all(|&b| b == (pg + i) as u8), "page {} gets its own data", pg + i);
                }
                match rand(10) {
                    0 => Err(os(libc::EEXIST)),
                    1 => {
                        // A REMOVE is queued; the event thread reads it.
                        p.read_gen.fetch_add(1, Ordering::SeqCst);
                        Err(os(libc::EAGAIN))
                    }
                    2 => Err(os(libc::EIO)),
                    _ => Ok(1 + rand(c)),
                }
            });
            // Only pages a failed install gave back can be REMOTE again by then.
            resolved += discarded;
            resolved += r;
            fetches += 1;
        }
        let s = states(&p);
        assert!(s.iter().all(|&s| s != INFLIGHT && s != DISCARDED), "{s:?}");
        assert_eq!(resolved, 64 - s.iter().filter(|&&s| s == REMOTE).count());
        // Failure history is kept only for pages still to come.
        let failing = p.failing.lock().unwrap();
        assert!(failing.iter().all(|&(pg, _)| s[pg] == REMOTE), "{failing:?} {s:?}");
        assert_eq!(p.failing_len.load(Ordering::SeqCst), failing.len());
    }
    assert!(fetches > 5000);
}

/// A page that fails to install is remembered (with when it first failed) until it goes in or is discarded, however it
/// gets claimed again; its neighbours that did go in are not.
#[test]
fn failure_history_follows_the_pages() {
    let p = pages(&[REMOTE; 8]);
    let enomem = |fail: usize| {
        move |pg: usize, c: usize| {
            if (pg..pg + c).contains(&fail) {
                if pg == fail {
                    Err(os(libc::ENOMEM))
                } else {
                    Ok(fail - pg)
                }
            } else {
                Ok(c)
            }
        }
    };
    p.claim(0, 4, REMOTE, |_| true);
    assert!(p.install(0, 4, REMOTE, None, enomem(2)).1.is_err());
    assert_eq!(states(&p)[..4], [PRESENT, PRESENT, REMOTE, REMOTE]);
    let first = p.failing_since(0, 8).expect("page 2 noted");
    assert_eq!(p.failing_since(0, 2), None, "pages that went in are not");
    assert_eq!(p.failing_since(3, 1), None, "nor ones given back unattempted");
    // Claimed again (by anyone) and failing again: the first time sticks.
    thread::sleep(Duration::from_millis(5));
    p.claim(2, 2, REMOTE, |_| true);
    assert!(p.install(2, 2, REMOTE, None, enomem(2)).1.is_err());
    assert_eq!(p.failing_since(2, 1), Some(first));
    // In at last: forgotten.
    p.claim(2, 2, REMOTE, |_| true);
    assert!(p.install(2, 2, REMOTE, None, |_, c| Ok(c)).1.is_ok());
    assert_eq!(p.failing_since(0, 8), None);
    assert_eq!(p.failing_len.load(Ordering::SeqCst), 0);
    // Discarded instead, while given back or while claimed: forgotten too.
    for claimed in [false, true] {
        let p = pages(&[REMOTE; 2]);
        p.claim(0, 2, REMOTE, |_| true);
        assert!(p.install(0, 2, REMOTE, None, enomem(0)).1.is_err());
        assert!(p.failing_since(0, 1).is_some());
        if claimed {
            p.claim(0, 1, REMOTE, |_| true);
        }
        discard(&p, 0);
        if claimed {
            assert!(p.install(0, 1, REMOTE, None, |_, _| panic!("discarded")).1.is_ok());
        }
        assert_eq!(p.failing_since(0, 2), None, "claimed {claimed}");
        assert_eq!(p.failing_len.load(Ordering::SeqCst), 0);
    }
}

/// A streamed install that fails installs nothing more, but reads the rest of the reply, so that the connection lives
/// on for the retry; a stopped pager cuts the fetch at once.
#[test]
fn failed_install_drains_the_fetch() {
    for stopped in [false, true] {
        let p = pages(&[REMOTE; 64]);
        p.claim(0, 64, REMOTE, |_| true);
        let mut delivered = 0;
        let mut fetch = |_: u64, buf: &mut [u8], _: &AtomicBool, progress: &mut dyn FnMut(&[u8]) -> bool| -> io::Result<()> {
            for k in 1..=buf.len() / PAGE_SIZE {
                delivered = k;
                if !progress(&buf[..k * PAGE_SIZE]) {
                    return Err(io::Error::other(FetchFailure::Cancelled));
                }
            }
            Ok(())
        };
        let stop = AtomicBool::new(stopped);
        let mut installs = 0;
        let (resolved, res) = p.fetch_install(0, 64, &mut vec![0u8; 64 * PAGE_SIZE], &mut fetch, &stop, &mut |_| true, |pg, _, _| {
            installs += 1;
            match pg {
                0 => Ok(1),
                _ => Err(os(libc::ENOMEM)),
            }
        });
        assert!(matches!(res, Err(Failed::Install(_))));
        assert_eq!(resolved, 1);
        assert_eq!(installs, 2, "nothing installed after the failure");
        let want = if stopped { 1 + STREAM_RUN } else { 64 };
        assert_eq!(delivered, want, "stopped: {stopped}");
        assert!(states(&p)[1..].iter().all(|&s| s == REMOTE));
        assert!(p.failing_since(1, 1).is_some());
    }
}

/// Faults waiting on claimed pages are woken when they settle, whether installed, given back or discarded; with none
/// waiting, nobody is.
#[test]
fn settling_wakes_waiting_faults() {
    let p = pages(&[REMOTE; 8]);
    let fd = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC) };
    assert!(fd >= 0);
    p.wake.set(unsafe { OwnedFd::from_raw_fd(fd) }).unwrap();
    let woken = || {
        let mut n = 0u64;
        unsafe { libc::read(fd, (&mut n as *mut u64).cast(), 8) == 8 }
    };
    p.claim(0, 2, REMOTE, |_| true);
    assert!(p.install(0, 2, REMOTE, None, |_, n| Ok(n)).1.is_ok());
    assert!(!woken(), "nobody waits");
    p.waiting.store(true, Ordering::SeqCst);
    p.claim(2, 2, REMOTE, |_| true);
    assert!(p.install(2, 2, REMOTE, None, |_, n| Ok(n)).1.is_ok());
    assert!(woken(), "installed");
    p.claim(4, 2, REMOTE, |_| true);
    p.release(4, 2, REMOTE);
    assert!(woken(), "given back");
    p.claim(6, 2, REMOTE, |_| true);
    discard(&p, 6);
    discard(&p, 7);
    assert!(p.install(6, 2, REMOTE, None, |_, _| panic!("discarded pages are not copied")).1.is_ok());
    assert!(woken(), "discarded while claimed");
    assert!(!woken());
    assert_eq!(states(&p), [PRESENT, PRESENT, PRESENT, PRESENT, REMOTE, REMOTE, ZERO, ZERO]);
}

/// An install that hits EAGAIN (a REMOVE is queued) waits for the event thread to read events, then copies again.
#[test]
fn eagain_waits_for_events_read() {
    let p = pages(&[REMOTE; 2]);
    p.claim(0, 2, REMOTE, |_| true);
    let stop = AtomicBool::new(false);
    let mut calls = 0;
    thread::scope(|s| {
        s.spawn(|| {
            thread::sleep(Duration::from_millis(20));
            discard(&p, 1);
            p.events_read();
        });
        let (resolved, res) = p.install(0, 2, REMOTE, Some(&stop), |_, n| {
            calls += 1;
            match p.read_gen.load(Ordering::SeqCst) {
                0 => Err(os(libc::EAGAIN)),
                _ => Ok(n),
            }
        });
        assert!(res.is_ok());
        assert_eq!(resolved, 2);
    });
    assert!(calls >= 2);
    assert!(p.install_eagain.load(Ordering::SeqCst) >= 1);
    assert_eq!(states(&p), [PRESENT, ZERO]);
}

/// A fetch with a head asks for it on its own, pipelined ahead of the rest, and reports the head as soon as it is in.
#[test]
fn fetch_asks_for_the_head_first() {
    let (listener, source) = listen();
    let (headed, head_seen) = std::sync::mpsc::channel();
    // The rest is sent only once the head was reported (or never will be, without the rest): no clock to race.
    let server = thread::spawn(move || {
        let (s, _) = listener.accept().unwrap();
        let mut r = io::BufReader::new(s.try_clone().unwrap());
        let mut hello = String::new();
        io::BufRead::read_line(&mut r, &mut hello).unwrap();
        let mut reqs = [[0u8; 12]; 2];
        reqs.iter_mut().for_each(|q| r.read_exact(q).unwrap());
        assert_eq!(reqs.map(|q| request(&q)), [(8192, 4096), (12288, 3 * 4096)]);
        let mut s = s;
        s.write_all(b"{\"ok\": true}\n").unwrap();
        s.write_all(&[&[0u8][..], &[1u8; 4096]].concat()).unwrap();
        let reported = head_seen.recv_timeout(Duration::from_secs(10)).is_ok();
        s.write_all(&[&[0u8][..], &[2u8; 3 * 4096]].concat()).unwrap();
        reported
    });
    let mut c = PageClient::connect(&source).unwrap();
    let mut buf = vec![0u8; 4 * PAGE_SIZE];
    let mut progress = |data: &[u8]| {
        if data.len() >= PAGE_SIZE {
            let _ = headed.send(());
        }
        true
    };
    c.fetch(8192, &mut buf, PAGE_SIZE, &mut progress, Instant::now() + Duration::from_secs(30)).unwrap();
    assert!(server.join().unwrap(), "head reported before the rest was sent");
    assert!(buf[..PAGE_SIZE].iter().all(|&b| b == 1) && buf[PAGE_SIZE..].iter().all(|&b| b == 2));
}

/// A page server whose page `p` is all `p as u8`. Its first connection answers `first` requests only, then hangs up its
/// side; later ones answer all. Sends each connection's requests, as `(offset, len)`, down `seen` once the client hung
/// up.
fn fake_source(first: usize, seen: std::sync::mpsc::Sender<Vec<(u64, u32)>>) -> Source {
    let (listener, source) = listen();
    thread::spawn(move || {
        for (k, s) in listener.incoming().enumerate() {
            let (mut r, mut w) = accept_hello(s.unwrap());
            let mut reqs = Vec::new();
            let mut req = [0u8; 12];
            while r.read_exact(&mut req).is_ok() {
                let (off, len) = request(&req);
                reqs.push((off, len));
                if k == 0 && reqs.len() > first {
                    continue;
                }
                let mut out = vec![0u8];
                out.extend((0..len as u64).map(|i| ((off + i) / PAGE_SIZE as u64) as u8));
                w.write_all(&out).unwrap();
                if k == 0 && reqs.len() == first {
                    w.shutdown(std::net::Shutdown::Write).unwrap();
                }
            }
            let _ = seen.send(reqs);
        }
    });
    source
}

#[test]
fn queued_requests_are_pipelined_and_resent_after_a_reconnect() {
    let (tx, rx) = std::sync::mpsc::channel();
    // The first connection answers the head and the rest of the first run only.
    let source = fake_source(2, tx);
    let (lane, stop) = (Lane::default(), AtomicBool::new(false));
    let mut link = Link::new(source);
    link.fetch_with(Some(&lane), 0, &mut [], &stop, &mut |_| true).unwrap();
    // Reconnects must use the cached addresses, even if the original name can no longer resolve.
    link.source.addr = "invalid address".into();
    // Written as they are queued, before the fetcher reads any reply.
    for job in [(3, 2), (7, 1), (10, 3)] {
        lane.push((job.0, job.1, Instant::now()));
    }
    assert_eq!(lane.q.lock().unwrap().sent, 3);
    for (first, n) in [(3usize, 2usize), (7, 1), (10, 3)] {
        let mut buf = vec![0u8; n * PAGE_SIZE];
        link.fetch_with(Some(&lane), (first * PAGE_SIZE) as u64, &mut buf, &stop, &mut |_| true).unwrap();
        assert!(buf.chunks(PAGE_SIZE).enumerate().all(|(i, p)| p.iter().all(|&b| b as usize == first + i)), "run {first}+{n}");
        lane.pop();
    }
    let page = |p: u64| p * PAGE_SIZE as u64;
    let sz = PAGE_SIZE as u32;
    // All three went out on the first connection, the faulting page of each on its own; what was not answered went out
    // again on the next.
    let rest = vec![(page(7), sz), (page(10), sz), (page(11), 2 * sz)];
    assert_eq!(rx.recv().unwrap(), [vec![(page(3), sz), (page(4), sz)], rest.clone()].concat());
    drop((link, lane));
    assert_eq!(rx.recv().unwrap(), rest);
}

#[test]
fn a_fetch_ends_by_its_deadline_however_the_server_trickles() {
    let (listener, source) = listen();
    thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        s.write_all(b"{\"ok\": true}\n\0").unwrap();
        while s.write_all(&[7]).is_ok() {
            thread::sleep(Duration::from_millis(20));
        }
    });
    let mut c = PageClient::connect(&source).unwrap();
    let start = Instant::now();
    let e = c.fetch(0, &mut [0u8; PAGE_SIZE], 0, &mut |_| true, start + Duration::from_millis(200)).unwrap_err();
    assert_eq!(e.kind(), io::ErrorKind::TimedOut, "{e}");
    assert!(start.elapsed() < Duration::from_secs(5), "{:?}", start.elapsed());
}

/// A source that delivers steadily but too slowly for any one request to finish by its deadline: the pull goes on from
/// what arrived, and completes.
#[test]
fn a_slow_source_that_keeps_delivering_is_not_lost() {
    let (listener, source) = listen();
    let conns = Arc::new(AtomicUsize::new(0));
    let counted = conns.clone();
    thread::spawn(move || {
        for s in listener.incoming() {
            counted.fetch_add(1, Ordering::SeqCst);
            let s = s.unwrap();
            thread::spawn(move || {
                let (mut r, mut w) = accept_hello(s);
                let mut req = [0u8; 12];
                while r.read_exact(&mut req).is_ok() {
                    let (off, len) = request(&req);
                    let len = len as u64;
                    let _ = w.write_all(&[0]);
                    for p in (off..off + len).step_by(PAGE_SIZE) {
                        thread::sleep(Duration::from_millis(25));
                        if w.write_all(&[(p / PAGE_SIZE as u64) as u8; PAGE_SIZE]).is_err() {
                            return;
                        }
                    }
                }
            });
        }
    });
    let n = 32;
    let p = pages(&[REMOTE; 32]);
    p.claim(0, n, REMOTE, |_| true);
    let mut link = Link::new(source);
    let mut fetch = |off: u64, buf: &mut [u8], stop: &AtomicBool, progress: &mut dyn FnMut(&[u8]) -> bool| link.fetch_with(None, off, buf, stop, progress);
    let stop = AtomicBool::new(false);
    let mut got = vec![0u8; n];
    let (resolved, res) = p.fetch_install(0, n, &mut vec![0u8; n * PAGE_SIZE], &mut fetch, &stop, &mut |e| partial(e), |pg, c, src| {
        for i in 0..c {
            got[pg + i] = src[i * PAGE_SIZE];
        }
        Ok(c)
    });
    assert!(
        res.is_ok(),
        "{:?}",
        res.err().map(|e| match e {
            Failed::Fetch(e) | Failed::Install(e) => e.to_string(),
        })
    );
    assert_eq!(resolved, n);
    assert!(got.iter().enumerate().all(|(i, &b)| b as usize == i), "{got:?}");
    // 0.8 s of pages over 0.3 s deadlines: it reconnected, for the rest only.
    assert!(conns.load(Ordering::SeqCst) > 1);
}

#[test]
fn fault_latency_buckets() {
    for ns in [4u64, 5, 7, 8, 15, 16, 17, 100, 999, 1000, 123_456, 10_000_000_000] {
        let b = bucket(ns);
        assert!(bucket_floor(b) <= ns && ns < bucket_floor(b + 1), "{ns}: bucket {b} [{}, {})", bucket_floor(b), bucket_floor(b + 1));
    }
    let s = FaultStats::new();
    for us in 1..=100 {
        s.record(FETCHED, Duration::from_micros(us));
    }
    s.record(WAITED, Duration::from_millis(3));
    let r = s.report();
    assert_eq!(r["remote"]["count"], 100);
    let p50 = r["remote"]["p50_us"].as_f64().unwrap();
    assert!((40.0..=50.0).contains(&p50), "{p50}");
    assert_eq!(r["remote"]["max_us"], 100.0);
    assert_eq!(r["wait"]["count"], 1);
    assert_eq!(r["local"]["count"], 0);
    assert_eq!(r["local"]["p99_us"], 0.0);
}

#[test]
fn remote_among_picks_remote_pages() {
    let runs: Runs = vec![(10, 5, REMOTE), (15, 2, ZERO), (100, 1, REMOTE), (3, 2, REMOTE)];
    assert_eq!(remote_among(&runs, [0, 3, 4, 5, 9, 10, 14, 15, 16, 99, 100, 101]), vec![3, 4, 10, 14, 100]);
    assert!(remote_among(&Vec::new(), [1, 2]).is_empty());
}

#[test]
fn next_not_base_finds_every_state() {
    let mut st = vec![BASE; 300];
    for &i in &[0usize, 7, 8, 9, 63, 64, 65, 130, 299] {
        st[i] = PRESENT;
    }
    let p = pages(&st);
    for from in 0..300 {
        for end in from..=300 {
            let want = (from..end).find(|&i| st[i] != BASE).unwrap_or(end);
            assert_eq!(p.next_not(BASE, from, end), want, "from {from} end {end}");
        }
    }
    assert_eq!(p.next_not(BASE, 10, 1000), 63);
    for from in 0..300 {
        for end in from..=300 {
            let want = (from..end).find(|&i| st[i] != PRESENT).unwrap_or(end);
            assert_eq!(p.next_not(PRESENT, from, end), want, "PRESENT from {from} end {end}");
            assert_eq!(p.next_in(PRESENT, from, end), (from..end).find(|&i| st[i] == PRESENT).unwrap_or(end));
        }
    }

    // Untouched chunks are skipped without reading them.
    let mut p = Pages::new(3 * CHUNK + 5);
    assert_eq!(p.next_not(BASE, 0, p.len()), p.len());
    p.fill(2 * CHUNK + 7, 1, ZERO);
    assert_eq!(p.next_not(BASE, 0, p.len()), 2 * CHUNK + 7);
    assert_eq!(p.claim(CHUNK + 3, 2, BASE, |_| true), 2);
    assert_eq!(p.next_not(BASE, 0, p.len()), CHUNK + 3);
    assert_eq!(p.next_not(BASE, CHUNK + 5, p.len()), 2 * CHUNK + 7);
}

#[test]
fn fill_seeds_runs_and_marks_their_chunks() {
    let n = 64 * CHUNK + 3 * CHUNK + 9;
    let mut p = Pages::new(n);
    let runs = [(CHUNK - 2, 4, REMOTE), (3 * CHUNK, CHUNK, ZERO), (64 * CHUNK + 5, 2 * CHUNK, REMOTE), (n - 1, 1, ZERO)];
    for &(first, count, state) in &runs {
        p.fill(first, count, state);
    }
    // Out of bounds: ignored.
    p.fill(n, 5, REMOTE);
    p.fill(n - 1, usize::MAX, ZERO);
    let want = |i: usize| runs.iter().find(|&&(f, c, _)| (f..f + c).contains(&i)).map_or(BASE, |r| r.2);
    for i in 0..n {
        assert_eq!(p.get(i), want(i), "page {i}");
    }
    for c in 0..n.div_ceil(CHUNK) {
        let any = (c * CHUNK..((c + 1) * CHUNK).min(n)).any(|i| want(i) != BASE);
        assert_eq!(p.touched(c * CHUNK), any, "chunk {c}");
    }
    assert_eq!(p.next_in(ZERO, 0, n), 3 * CHUNK);
    assert_eq!(p.next_not(BASE, 4 * CHUNK, n), 64 * CHUNK + 5);
}

#[test]
fn claimed_pages_have_one_installer() {
    let p = pages(&[REMOTE, REMOTE, BASE, REMOTE]);
    assert_eq!(p.claim(0, 8, REMOTE, |_| true), 2);
    assert_eq!(p.claim(0, 8, REMOTE, |_| true), 0);
    assert_eq!(p.claim(3, 8, REMOTE, |i| i != 3), 0);
    let mut calls = Vec::new();
    let (resolved, res) = p.install(0, 2, REMOTE, None, |i, n| {
        calls.push((i, n));
        Ok(n)
    });
    assert!(res.is_ok());
    assert_eq!((resolved, calls), (2, vec![(0, 2)]));
    assert_eq!(states(&p), [PRESENT, PRESENT, BASE, REMOTE]);
}

#[test]
fn remove_during_copy_waits_for_settle() {
    // A REMOVE read while a copy is in progress is applied only after the copy has settled (and so before the kernel
    // zaps the range): the page ends ZERO, never PRESENT without its data.
    let p = pages(&[REMOTE; 2]);
    p.claim(0, 2, REMOTE, |_| true);
    let removed = AtomicBool::new(false);
    thread::scope(|scope| {
        let (resolved, res) = p.install(0, 2, REMOTE, None, |_, n| {
            scope.spawn(|| {
                discard(&p, 1);
                removed.store(true, Ordering::SeqCst);
            });
            thread::sleep(Duration::from_millis(50));
            assert!(!removed.load(Ordering::SeqCst), "REMOVE applied mid-copy");
            Ok(n)
        });
        assert!(res.is_ok());
        assert_eq!(resolved, 2);
    });
    assert!(removed.load(Ordering::SeqCst));
    assert_eq!(states(&p), [PRESENT, ZERO]);
}

#[test]
fn failed_fetch_gives_pages_back() {
    let p = pages(&[REMOTE; 3]);
    p.claim(0, 3, REMOTE, |_| true);
    discard(&p, 2);
    assert_eq!(p.release(0, 3, REMOTE), 1);
    assert_eq!(states(&p), [REMOTE, REMOTE, ZERO]);
    assert_eq!(p.claim(0, 3, REMOTE, |_| true), 2);
}

#[test]
fn partial_copies_and_errors() {
    // UFFDIO_COPY stops after two pages, the next one already exists, then EIO.
    let p = pages(&[REMOTE; 6]);
    p.claim(0, 6, REMOTE, |_| true);
    let mut script = vec![Ok(2), Err(os(libc::EEXIST)), Err(os(libc::EIO))].into_iter();
    let (resolved, res) = p.install(0, 6, REMOTE, None, |_, _| script.next().unwrap());
    assert_eq!(res.unwrap_err().raw_os_error(), Some(libc::EIO));
    assert_eq!(states(&p), [PRESENT, PRESENT, PRESENT, REMOTE, REMOTE, REMOTE]);
    assert_eq!(resolved, 3);
}

#[test]
fn eagain_retries_only_with_a_stop_flag() {
    let p = pages(&[BASE; 2]);
    p.claim(0, 2, BASE, |_| true);
    let (_, res) = p.install(0, 2, BASE, None, |_, _| Err(os(libc::EAGAIN)));
    assert_eq!(res.unwrap_err().raw_os_error(), Some(libc::EAGAIN));
    assert_eq!(states(&p), [BASE, BASE]);

    let stop = AtomicBool::new(false);
    p.claim(0, 2, BASE, |_| true);
    let mut script = vec![Err(os(libc::EAGAIN)), Ok(2)].into_iter();
    let (resolved, res) = p.install(0, 2, BASE, Some(&stop), |_, _| script.next().unwrap());
    assert!(res.is_ok());
    assert_eq!((states(&p), resolved), (vec![PRESENT, PRESENT], 0));
}

#[test]
fn prefetch_racing_remove() {
    let p = pages(&[BASE; 3]);
    p.claim(0, 3, BASE, |_| true);
    assert_eq!(p.claim(0, 3, BASE, |_| true), 0, "a fault waits for the prefetch");
    discard(&p, 0);
    let (_, res) = p.install(0, 3, BASE, None, |i, n| {
        assert_eq!((i, n), (1, 2));
        Ok(n)
    });
    assert!(res.is_ok());
    assert_eq!(states(&p), [ZERO, PRESENT, PRESENT]);
    // A discarded page whose neighbours fail to copy ends ZERO, not BASE.
    let p = pages(&[BASE; 2]);
    p.claim(0, 2, BASE, |_| true);
    discard(&p, 0);
    let (_, res) = p.install(0, 2, BASE, None, |_, _| Err(os(libc::ENOMEM)));
    assert!(res.is_err());
    assert_eq!(states(&p), [ZERO, BASE]);
}

#[test]
fn incoming_runs_are_validated() {
    let map = |spans: &[(usize, usize)]| -> Vec<Mapping> {
        spans.iter().map(|&(a, b)| Mapping { base_host_virt_addr: 0, offset: (a * PAGE_SIZE) as u64, size: (b - a) * PAGE_SIZE }).collect()
    };
    let one = map(&[(0, 10)]);
    assert_eq!(remote_pages(&vec![(0, 2, REMOTE), (2, 3, ZERO), (8, 2, REMOTE)], &one).unwrap(), 4);
    // Regions [0, 4) and [4, 6) (adjacent) and [8, 10), listed in any order: runs may cross adjacent regions, not gaps.
    let gapped = map(&[(8, 10), (4, 6), (0, 4)]);
    assert_eq!(remote_pages(&vec![(0, 6, REMOTE), (8, 2, ZERO)], &gapped).unwrap(), 6);
    for bad in [vec![(5, 2, REMOTE)], vec![(6, 2, REMOTE)], vec![(7, 2, ZERO)], vec![(9, 2, REMOTE)], vec![(10, 1, REMOTE)]] {
        assert!(remote_pages(&bad, &gapped).is_err(), "{bad:?}");
    }
    for bad in [
        vec![(0, 2, REMOTE), (1, 2, REMOTE)],
        vec![(4, 2, REMOTE), (0, 2, REMOTE)],
        vec![(9, 2, REMOTE)],
        vec![(u64::MAX, 2, REMOTE)],
        vec![(0, 0, REMOTE)],
        vec![(0, 1, INFLIGHT)],
        vec![(0, 1, DISCARDED)],
        vec![(0, 1, PRESENT)],
    ] {
        assert!(remote_pages(&bad, &one).is_err(), "{bad:?}");
    }
}

/// Random interleavings of claims, REMOVEs (including while a claim's fetch is in flight), partial copies, errors and
/// failed fetches: no page stays claimed and every REMOTE page is counted as resolved exactly once.
#[test]
fn remote_accounting_adds_up() {
    let mut seed = 0x9e37_79b9_7f4a_7c15u64;
    let mut rand = move |n: usize| {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        (seed % n as u64) as usize
    };
    for _ in 0..200 {
        let p = pages(&[REMOTE; 64]);
        let mut resolved = 0;
        for _ in 0..200 {
            let first = rand(64);
            if rand(4) == 0 {
                resolved += discard(&p, first) as usize;
                continue;
            }
            let n = p.claim(first, 1 + rand(16), REMOTE, |_| true);
            if n == 0 {
                continue;
            }
            if rand(4) == 0 {
                resolved += p.release(first, n, REMOTE);
                continue;
            }
            for _ in 0..rand(3) {
                assert!(!discard(&p, first + rand(n)));
            }
            let mut script = Vec::new();
            for _ in 0..8 {
                script.push((rand(5), rand(64)));
            }
            let mut script = script.into_iter();
            let (r, _) = p.install(first, n, REMOTE, None, |_, m| {
                let (outcome, k) = script.next().unwrap_or((4, 0));
                match outcome {
                    0 => Err(os(libc::EEXIST)),
                    1 => Err(os(libc::EAGAIN)),
                    2 => Err(os(libc::EIO)),
                    _ => Ok(1 + k % m),
                }
            });
            resolved += r;
        }
        let s = states(&p);
        assert!(s.iter().all(|&s| s != INFLIGHT && s != DISCARDED), "{s:?}");
        assert_eq!(resolved, 64 - s.iter().filter(|&&s| s == REMOTE).count());
    }
}

#[test]
fn failures_are_classified_by_type() {
    assert!(!fatal(&io::Error::new(io::ErrorKind::TimedOut, "transport timeout")));
    assert!(!fatal(&io::Error::new(io::ErrorKind::InvalidData, "transport data")));
    for failure in [FetchFailure::SourceLost("source lost".into()), FetchFailure::Checkpoint(os(libc::EIO))] {
        assert!(fatal(&io::Error::other(failure)));
    }
    assert!(partial(&io::Error::other(FetchFailure::Partial("short read".into()))));
    assert!(!partial(&io::Error::other(FetchFailure::Cancelled)));
}

#[test]
fn zeroed_atomic_arrays_are_aligned_and_writable() {
    let bytes: Vec<std::sync::atomic::AtomicU8> = zeroed_atomics(3);
    let words: Vec<AtomicU64> = zeroed_atomics(65);
    assert!(bytes.iter().all(|a| a.load(Ordering::SeqCst) == 0));
    assert!(words.iter().all(|a| a.load(Ordering::SeqCst) == 0));
    words[64].store(u64::MAX, Ordering::SeqCst);
    assert_eq!(words[64].load(Ordering::SeqCst), u64::MAX);
    assert!(zeroed_atomics::<AtomicU64>(0).is_empty());
}

#[test]
fn prefetch_ordering_preserves_learning_and_load_completion() {
    // All six-event sequences, including repeated notifications and learning after load.
    for mut sequence in 0..3usize.pow(6) {
        let mut state = PrefetchState::Idle;
        let (mut loaded, mut due, mut learning) = (false, false, false);
        for _ in 0..6 {
            let event = sequence % 3;
            sequence /= 3;
            if event == 0 {
                learning = true;
                state.learn();
            } else {
                loaded |= event == 1;
                learning &= event != 1;
                due |= event == 2;
                let start = due && (loaded || !learning);
                assert_eq!(state.request(event == 1, event == 2), start);
                due &= !start;
            }
            assert_eq!(state.learning(), learning);
        }
    }
}

#[test]
fn protect_ranges_stay_bounded() {
    use super::wp::{protect_ranges, PROTECT_MAX};
    // Merged across gaps of up to 64 pages, and not across a kept page.
    assert_eq!(protect_ranges([0, 65, 131].into_iter(), &[]), vec![(0, 66), (131, 132)]);
    assert_eq!(protect_ranges([0, 10].into_iter(), &[5]), vec![(0, 1), (10, 11)]);
    assert_eq!(protect_ranges([0, 10].into_iter(), &[11]), vec![(0, 11)]);
    // Every 66th page of a 32 GiB region: 127,101 ranges at that gap, merged down to a bounded count, covering every
    // page and no kept one.
    let n = 32 << 18;
    let kept: Vec<usize> = (7..n).step_by(1 << 20).collect();
    let pages: Vec<usize> = (0..n).step_by(66).filter(|p| kept.binary_search(p).is_err()).collect();
    let covers = |ranges: &[(usize, usize)], pages: &[usize], kept: &[usize]| {
        assert!(ranges.windows(2).all(|w| w[0].1 < w[1].0));
        let mut r = ranges.iter().peekable();
        for &p in pages {
            while r.peek().is_some_and(|&&(_, e)| e <= p) {
                r.next();
            }
            assert!(r.peek().is_some_and(|&&(f, _)| f <= p), "page {p} not protected");
        }
        assert!(ranges.iter().all(|&(f, e)| !kept.iter().any(|k| (f..e).contains(k))));
    };
    let ranges = protect_ranges(pages.iter().copied(), &kept);
    assert!(ranges.len() <= PROTECT_MAX, "{} ranges", ranges.len());
    covers(&ranges, &pages, &kept);
    // A kept page just before each of 4,098 dirty ones 2047 pages apart: nothing can merge, so every pass runs to
    // the region's span. A walk along the kept pages, not a lookup per page of every gap, keeps that fast: a few ms,
    // where a scan of every gap page takes seconds. Loose enough for a loaded test runner.
    let kept: Vec<usize> = (1..=4098).map(|i| 2047 * i - 1).collect();
    let pages: Vec<usize> = (1..=4098).map(|i| 2047 * i).collect();
    let start = std::time::Instant::now();
    let ranges = protect_ranges(pages.iter().copied(), &kept);
    assert!(start.elapsed() < std::time::Duration::from_secs(2), "{:?}", start.elapsed());
    assert_eq!(ranges.len(), pages.len());
    covers(&ranges, &pages, &kept);
}
