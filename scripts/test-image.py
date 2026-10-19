#!/usr/bin/env python3
"""Makes the test image: Firecracker CI's ubuntu 24.04 root filesystem (scripts/fetch.sh puts it
in STATE/artifacts/base.squashfs), which has what the tests run in their guests (python3, socat,
iproute2, procps), as an OCI image layout directory. It has no command, so its VMs idle until
told what to run, and the same squashfs always makes the same image (one uncompressed layer
with fixed times and numeric owners, and no creation date), so flexvm's image cache keeps it.

    sudo scripts/test-image.py /var/lib/flexvm-test-image
    sudo flexvm pull /var/lib/flexvm-test-image --tag small --vcpus 2 --max 2048

scripts/e2e.py makes and pulls it for its templates. A directory that already holds the image
of the same squashfs is left as it is. OUT must be missing, empty, or an existing
test image (oci-layout and source.sha256). Use a root-owned location for OUT.

usage: sudo scripts/test-image.py [--state DIR] [--squashfs FILE] OUT
"""
import argparse, hashlib, json, os, shutil, subprocess, sys, tempfile

p = argparse.ArgumentParser(usage=__doc__)
p.add_argument("--state", default=os.environ.get("FLEXVM_STATE_DIR") or "/var/lib/flexvm")
p.add_argument("--squashfs", help="default: STATE/artifacts/base.squashfs")
p.add_argument("out")
args = p.parse_args()
squashfs = args.squashfs or os.path.join(args.state, "artifacts", "base.squashfs")
out = os.path.abspath(args.out)
EPOCH = 1700000000


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


def check_out():
    if not os.path.lexists(out):
        return
    if os.path.islink(out) or not os.path.isdir(out):
        sys.exit(f"refusing {out}: OUT must be a directory, not a symlink")
    if os.listdir(out) and not all(os.path.isfile(os.path.join(out, name))
                                   for name in ("oci-layout", "source.sha256")):
        sys.exit(f"refusing {out}: non-empty OUT is not a test image (needs oci-layout and source.sha256)")


check_out()
source = sha256_file(squashfs)
stamp = os.path.join(out, "source.sha256")
if os.path.exists(os.path.join(out, "index.json")) and os.path.exists(stamp) and open(stamp).read().strip() == source:
    print(f"{out}: the test image of {squashfs} already")
    sys.exit(0)
if os.geteuid() != 0:
    sys.exit("run as root: the root filesystem has setuid files and device nodes")

parent = os.path.dirname(out)
os.makedirs(parent, exist_ok=True)
# Root-only, beside OUT (on disk, not a tmpfs): the unpacked tree has setuid files and device nodes.
work = tempfile.mkdtemp(prefix=".test-image-", dir=parent)
try:
    os.chmod(work, 0o700)
    root, layout = os.path.join(work, "root"), os.path.join(work, "layout")
    subprocess.run(["unsquashfs", "-q", "-d", root, squashfs], check=True, stdout=subprocess.DEVNULL)
    blobs = os.path.join(layout, "blobs", "sha256")
    os.makedirs(blobs)
    layer = os.path.join(work, "layer.tar")
    subprocess.run(["tar", "-C", root, "--sort=name", f"--mtime=@{EPOCH}", "--numeric-owner", "--format=posix",
                    "--pax-option=exthdr.name=%d/PaxHeaders/%f,delete=atime,delete=ctime",
                    "--xattrs", "--xattrs-include=*", "-cf", layer, "."], check=True)

    def blob(data=None, path=None):
        digest = hashlib.sha256(data).hexdigest() if path is None else sha256_file(path)
        dest = os.path.join(blobs, digest)
        if path is None:
            with open(dest, "wb") as f:
                f.write(data)
        else:
            os.rename(path, dest)
        return {"digest": "sha256:" + digest, "size": os.path.getsize(dest)}

    layer_desc = {"mediaType": "application/vnd.oci.image.layer.v1.tar", **blob(path=layer)}
    config = {"architecture": "amd64", "os": "linux",
              "config": {"Env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"]},
              "rootfs": {"type": "layers", "diff_ids": [layer_desc["digest"]]}}
    config_desc = {"mediaType": "application/vnd.oci.image.config.v1+json", **blob(json.dumps(config, sort_keys=True).encode())}
    manifest = {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json", "config": config_desc, "layers": [layer_desc]}
    manifest_desc = {"mediaType": manifest["mediaType"], **blob(json.dumps(manifest, sort_keys=True).encode())}
    with open(os.path.join(layout, "index.json"), "w") as f:
        json.dump({"schemaVersion": 2, "manifests": [manifest_desc]}, f)
    with open(os.path.join(layout, "oci-layout"), "w") as f:
        json.dump({"imageLayoutVersion": "1.0.0"}, f)
    with open(os.path.join(layout, "source.sha256"), "w") as f:
        f.write(source + "\n")
    # Readable by whoever pulls it (the blobs are checked against their digests anyway).
    for d, _, files in os.walk(layout):
        os.chmod(d, 0o755)
        for name in files:
            os.chmod(os.path.join(d, name), 0o644)
    check_out()
    old = os.path.join(work, "old")
    if os.path.lexists(out):
        os.rename(out, old)
    try:
        os.rename(layout, out)
    except OSError:
        if os.path.exists(old):
            os.rename(old, out)
        raise
    print(f"{out}: test image {manifest_desc['digest']} ({layer_desc['size'] >> 20} MiB layer) from {squashfs}")
finally:
    shutil.rmtree(work, ignore_errors=True)
