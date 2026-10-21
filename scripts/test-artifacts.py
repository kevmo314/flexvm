#!/usr/bin/env python3
"""Release pin tests: temporary checkouts and fake downloads, no network or VMs."""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent


class Pins(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name in ('scripts', 'firecracker', '.github', 'flexvm', 'guest'):
            (self.root / name).mkdir()
        for name in ('versions.sh', 'fetch.sh', 'pin-artifacts.sh', 'release-assets.sh', 'build-firecracker.sh'):
            shutil.copy2(ROOT / 'scripts' / name, self.root / 'scripts' / name)
        shutil.copytree(ROOT / 'firecracker', self.root / 'firecracker', dirs_exist_ok=True)
        shutil.copytree(ROOT / '.github/workflows', self.root / '.github/workflows')
        for name in ('flexvm', 'guest'):
            (self.root / name / 'Cargo.toml').write_text('version = "0.2.1"\n')
        self.checksums = self.root / 'scripts/checksums.sha256'
        self.checksums.write_text('')
        self.env = dict(os.environ, ARTIFACTS_TAG='v0.2.1', FC_VERSION='v1.17.0', CI_VERSION='v1.15', KERNEL='vmlinux-6.1.155')
        self.url = 'https://github.com/numerataz/flexvm/releases/download/v0.2.1'
        self.kernel = 'https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.15/x86_64/vmlinux-6.1.155'
        self.digest = 'a' * 64

    def run_script(self, name, *args):
        return subprocess.run(['bash', str(self.root / 'scripts' / name), *args], env=self.env, text=True, capture_output=True)

    def pinned(self):
        return subprocess.run(['bash', '-c', 'root=$1; source "$root/scripts/versions.sh"; pinned "$2"',
                               'test', str(self.root), self.url], env=self.env, text=True, capture_output=True)

    def test_validator(self):
        for data, status in [('', 2), (f'{self.digest} {self.url}\n', 0),
                             (f'{self.digest.upper()}\t{self.url}\n', 0),
                             (f'# unrelated\n{self.digest} {self.url}/other\n', 2),
                             (f'{self.url}\n', 1), (f'bad {self.url}\n', 1),
                             (f'{self.url} {self.digest}\n', 1), (f'extra {self.digest} {self.url}\n', 1),
                             (f'{self.digest} {self.url} extra\n', 1),
                             (f'{self.digest} {self.url}\n' * 2, 1),
                             (f'{self.digest} {self.url}\n{self.url}\n', 1)]:
            with self.subTest(data=data):
                self.checksums.write_text(data)
                result = self.pinned()
                self.assertEqual(result.returncode, status, result.stderr)
                if status == 0:
                    self.assertEqual(result.stdout.strip().lower(), self.digest)
        self.checksums.unlink()
        self.assertEqual(self.pinned().returncode, 1)

    def test_fetch_fallback(self):
        result = self.run_script('fetch.sh', '--urls')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('firecracker-v1.17.0-x86_64.tgz', result.stdout)
        self.assertIn(self.kernel, result.stdout)
        self.checksums.write_text(''.join(f'{self.digest} {self.url}/{asset}\n' for asset in ('firecracker', 'vmlinux')))
        result = self.run_script('fetch.sh', '--urls')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f'firecracker {self.url}/firecracker\n', result.stdout)
        self.assertIn(f'vmlinux {self.url}/vmlinux\n', result.stdout)

    def test_malformed_release_never_falls_back(self):
        for asset in ('firecracker', 'vmlinux'):
            for line in (f'bad {self.url}/{asset}\n', f'{self.url}/{asset}\n',
                         f'{self.digest} {self.url}/{asset}\n' * 2):
                with self.subTest(asset=asset, line=line):
                    self.checksums.write_text(line)
                    result = self.run_script('fetch.sh', '--urls')
                    self.assertEqual(result.returncode, 1)
                    self.assertIn('Malformed SHA256', result.stderr)
                    self.assertEqual(result.stdout, '')

    def test_inputs_reject_bad_kernel(self):
        self.checksums.write_text(f'{self.digest} {self.kernel}\n' * 2)
        result = self.run_script('pin-artifacts.sh', '--inputs')
        self.assertEqual(result.returncode, 1)
        self.assertIn('Malformed SHA256', result.stderr)

    def test_check_pins(self):
        upstream = f'{self.digest} {self.kernel}\n'
        self.checksums.write_text(upstream)
        result = self.run_script('pin-artifacts.sh', '--inputs')
        self.assertEqual(result.returncode, 0, result.stderr)
        digest = hashlib.sha256(result.stdout.encode()).hexdigest()
        pins = f'{self.digest} {self.url}/firecracker\n{self.digest} {self.url}/vmlinux\n{digest} {self.url}/inputs.txt\n'
        self.checksums.write_text(upstream + pins)
        result = self.run_script('pin-artifacts.sh', '--check')
        self.assertEqual(result.returncode, 0, result.stderr)
        for asset in ('firecracker', 'vmlinux', 'inputs.txt'):
            self.checksums.write_text(upstream + pins + f'{self.url}/{asset}\n')
            result = self.run_script('pin-artifacts.sh', '--check')
            self.assertEqual(result.returncode, 1)
            self.assertIn('Malformed SHA256', result.stderr)

    def test_atomic_pins(self):
        assets = self.root / 'assets'
        assets.mkdir()
        (assets / 'firecracker').write_text('not executable')
        (assets / 'vmlinux').write_text('kernel')
        kernel = hashlib.sha256(b'kernel').hexdigest()
        original = f'{kernel} {self.kernel}\n{self.digest} https://unrelated\n'
        self.checksums.write_text(original)
        self.checksums.chmod(0o644)
        inputs = self.run_script('pin-artifacts.sh', '--inputs')
        self.assertEqual(inputs.returncode, 0, inputs.stderr)
        (assets / 'inputs.txt').write_text(inputs.stdout)
        commands = self.root / 'bin'
        commands.mkdir()
        self.env.update(PATH=f'{commands}:{os.environ["PATH"]}', TEST_ASSETS=str(assets))
        mocks = {
            'curl': 'cp "$TEST_ASSETS/${4##*/}" "$3"',
            'gh': 'exit 0',
            'git': 'case " $* " in *" ls-remote "*) printf "%040d\\trefs/tags/v0.2.1\\n" 1;; *" merge-base "*) exit 0;; *) exit 1;; esac',
            'mv': 'echo simulated-rename-failure >&2; exit 1',
        }
        for name, body in mocks.items():
            path = commands / name
            path.write_text('#!/usr/bin/env bash\nset -eu\n' + body + '\n')
            path.chmod(0o755)
        result = self.run_script('pin-artifacts.sh')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('simulated-rename-failure', result.stderr)
        self.assertEqual(self.checksums.read_text(), original)
        self.assertEqual(list(self.checksums.parent.glob('checksums.sha256.*')), [])
        (commands / 'mv').unlink()
        result = self.run_script('pin-artifacts.sh')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.checksums.read_text().startswith(original))
        self.assertEqual(self.checksums.stat().st_mode & 0o777, 0o644)
        for asset in ('firecracker', 'vmlinux', 'inputs.txt'):
            digest = hashlib.sha256((assets / asset).read_bytes()).hexdigest()
            self.assertIn(f'{digest} {self.url}/{asset}\n', self.checksums.read_text())


if __name__ == '__main__':
    unittest.main()
