# Container images

```sh
sudo flexvm pull nginx:1.27                                     # any registry: Docker Hub, ghcr.io, gcr.io, ...
sudo flexvm pull ./app.tar --tag app --env PORT=8080            # `docker save` output or an OCI archive
sudo flexvm pull ./oci-layout --tag py --cmd "python3 -m http.server 8000"
sudo flexvm pull nginx:1.27 --tag web-warm --warm               # snapshot nginx running and ready
flexvm run --name web1 nginx:1.27
curl http://<ip>/
```

`IMAGE` is a registry reference (`nginx`, `ghcr.io/org/app@sha256:…`), an
uncompressed `docker save` / OCI archive, or an OCI image layout directory
(these two need `--tag NAME[:TAG]`: flexvm does not read the names inside).
Names, pulling again, `images` and `rmi` are in the README
([Images](../README.md#images)). Overrides follow `docker run`:
`--entrypoint` and `--cmd` (words, or a JSON array; a new entrypoint drops
the image's command), `--env K=V` (repeatable), `--workdir`,
`--user name|uid[:group|gid]`. An image left with no entrypoint and no
command has no app: its VMs idle (`--warm` refuses it).

Images are untrusted input processed as root. Every document and blob is
checked against its digest (layers while unpacking into private staging,
and their uncompressed contents against the config's `diff_ids`, all before
publishing the root filesystem), and builds are bounded: `--max-download-mib`
(8192, all layers compressed), `--max-unpacked-mib` (16384), `--max-file-mib` (4096),
`--max-entries` (1,000,000, applied both to tar entries read and to files and
directories created, implicit parents included), plus 4 MiB per manifest or config and 1 MiB per
tar entry's metadata (PAX records and GNU long names together, one of each).
Readiness commands run as the app does (same user and restrictions) in a
cgroup of their own that is killed and checked empty when the check ends; a
failed cleanup fails the check. Non-root checks need cgroup2 with
`cgroup.kill` and fail closed without it. Root checks are trusted (root in
the guest can leave any cgroup); without cgroup2 their session is killed.

- **Pull.** Native registry v2 client (no docker or skopeo): anonymous bearer
  tokens, or basic credentials from `$DOCKER_CONFIG`, `~/.docker/config.json`
  or, under sudo, the invoking user's. Indexes resolve to linux/amd64. Blobs
  are streamed to `STATE/images/blobs/sha256/` and checked against their
  digests; gzip, zstd and uncompressed layers are supported. Archives are read
  in place (layers are located inside the tarball, not extracted). Registry
  credentials go only over HTTPS to the registry itself or its token service
  (auth.docker.io for Docker Hub); redirects to blob storage carry none.
- **Root filesystem.** Layers are applied in order as root, with whiteouts and
  opaque directories, ownership, modes, xattrs, device nodes, symlinks and
  hard links. Every path resolves inside the image (`openat2(RESOLVE_IN_ROOT)`),
  so absolute symlinks behave as in a container and a layer cannot write
  outside it; whiteouts must name one entry, and removal walks directory fds.
  Layers are unpacked in `STATE/staging` (default `/var/lib/flexvm/staging`),
  which must be root-owned and 0700 with an ancestry only root can change, and
  is used through a descriptor, so other users can neither reach the image's
  setuid files and device nodes nor swap the directory mid-build. A build
  unpacks into `rootfs-<random>` there, flocked through `rootfs-<random>.lock`
  beside it; interrupted (SIGINT, SIGTERM, SIGHUP) it removes that tree and its
  half-written `<key>.tmp<random>` before exiting, and a killed build's are
  removed by the next build, once their locks are free. The image
  cache is trusted by whoever can write it (it is reused as is); writes into it
  never follow symlinks. flexvm adds `/sbin/flexvm-init`, its mount points,
  `/etc/flexvm/app.conf` (argv, env, workdir, uid/gid/groups resolved against
  the image's own `/etc/passwd` and `/etc/group`), an `/etc/hosts`, and an
  empty `/etc/resolv.conf` if the image has none (host.json's `dns` fills
  it at `run`). `mkfs.ext4 -d` writes the read-only image. Built filesystems
  are cached in `STATE/images/rootfs/` by image config digest, flexvm-init
  and overrides, and templates attach the cached file in place, so templates of
  one image share one copy in the page cache (it is never rewritten; `rmi`
  removes it once no template uses it, and deleting it by hand breaks those
  templates). Builds of the same cache key are serialized with
  a lock; entries are published with fsync and no-replace rename, with their
  `.ok` marker last. Every reuse also fsyncs the cache directory under the
  lock; a failed fsync refuses the entry. Templates only ever get durably
  marked entries, so a build that finds an unmarked one (an interrupted
  build) removes it and rebuilds; a marked entry with missing files is
  refused. The template's content ID covers that file as its `rootfs`
  component plus the image's manifest and config digests and the
  app config, so it differs whenever the image does.
- **Process.** flexvm-init stays PID 1. It starts the entrypoint in its own
  session with the image's env, workdir and credentials, reaps it and records
  its exit status, and keeps its stdout and stderr (interleaved) in a 1 MiB
  ring, which the VM process copies to its stdout (`RUN/vms/NAME.log` for a
  background VM), and follows it across migrations, suspends and
  checkpoints (its offset in the ring goes with them, so nothing is printed
  twice; a reader that fell behind the ring goes on from its start, saying
  how much was lost, and an offset past the ring's end goes on from that
  end, saying so). There is no restart policy. Nothing beyond the entrypoint is
  assumed: distroless and scratch images work, and `flexvm exec` on an image
  without `/bin/sh` fails (exit 1) with a message saying so. `/dev/stdout` and
  friends exist, so images that log to them work. With a non-root `--user`
  (or image `User`), the app runs with `no_new_privs` and no capabilities in
  its bounding set, so setuid binaries and file capabilities in the image do
  not work for it (and cannot make it root again); flexvm-init is not
  dumpable, so such an app cannot ptrace or read it. That does not stop an
  app running as root with `CAP_SYS_PTRACE`, which can reach flexvm-init
  anyway (root in the guest owns the guest).
- **When the app starts.** By default at `run`: the snapshot is an idle booted
  guest and `run` sends `APP` after the address is set (`app_start`, ~17 ms
  for nginx), then the app starts as it would anywhere. With `--warm` the
  template starts the app, waits until it is ready (`--ready-port N`: something
  accepts on 127.0.0.1:N in the guest, default the lowest exposed TCP port;
  `--ready-cmd CMD`: a shell command exits 0, killed when the deadline passes; `--ready-timeout S`, default 120)
  and snapshots it running.

> **`--warm` clones share userland state.** Every VM restored from a warm
> template starts from the same memory: anything the app generated before the
> snapshot (RNG seeds, session and TLS keys, UUIDs, tokens, caches) is
> identical in every clone. Firecracker's VMGenID makes the guest kernel
> reseed its RNG on restore, but nothing tells the app. Only use `--warm` for
> apps that hold no secrets or per-instance identity at startup, or that
> regenerate them per connection from the kernel RNG.
