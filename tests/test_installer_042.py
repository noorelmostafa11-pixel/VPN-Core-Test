"""Test overlay/rollback logic on Linux; Windows runtime remains unverified."""
import hashlib,json,os,pathlib,shutil,subprocess,tempfile,unittest
from test_core import ROOT,BIN
from test_batch import PW
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
@unittest.skipUnless(PW and os.name=='posix','Requires PowerShell and fixture executables')
class InstallerTests(unittest.TestCase):
    def fixture(self,temp,fail=False):
        temp=pathlib.Path(temp);package=temp/'package';project=temp/'project'
        manifest=json.loads((ROOT/'patch-manifest.json').read_text())
        for entry in manifest['files']:
            for directory in (package,project):
                path=directory/entry['path'];path.parent.mkdir(parents=True,exist_ok=True)
                shutil.copy2(ROOT/entry['path'],path)
        shutil.copy2(ROOT/'Install-Fix.ps1',package/'Install-Fix.ps1')
        # Exercise the actual compiled Linux core/component, then an explicit
        # failing child for rollback. These fixtures do not claim Windows tests.
        for directory in (project,package):
            shutil.copy2(BIN,directory/'bin/vpn-core.exe');shutil.copy2(ROOT/'bin/libvpn-tls.so',directory/'bin/libvpn-tls.so')
        if fail:
            exe=package/'bin/vpn-core.exe';exe.write_text('#!/bin/sh\nexit 23\n');exe.chmod(0o700)
        for entry in manifest['files']:entry['sha256']=sha(package/entry['path'])
        manifest['allowed_core_hashes']=[sha(project/'bin/vpn-core.exe')];manifest['allowed_provider_hashes']=[sha(project/'bin/vpn-tls.dll')]
        (package/'patch-manifest.json').write_text(json.dumps(manifest))
        batch=project/'scripts/Test-Batch.ps1';s=batch.read_text().replace('$TimeoutSeconds = 20','$TimeoutSeconds = 7').replace("$Url = 'https://example.com/'","$Url = 'https://example.com/user-path?x=1&y=2'").replace('$Concurrency = 8','$Concurrency = 12');batch.write_text(s)
        (project/'nodes').mkdir();(project/'nodes/unchanged.txt').write_bytes(b'original node bytes\r\n');(project/'batch-results-existing').mkdir();(project/'batch-results-existing/sentinel').write_bytes(b'existing report')
        # Newly added files must be removed on rollback.
        if fail:(project/'tls-provider/diagnostics.go').unlink()
        return package,project,manifest
    def invoke(self,package,project):return subprocess.run([PW,'-NoProfile','-File',str(package/'Install-Fix.ps1'),'-Project',str(project)],capture_output=True,text=True,timeout=30)
    def test_install_preserves_defaults_nodes_and_reports(self):
        with tempfile.TemporaryDirectory() as td:
            package,project,manifest=self.fixture(td);run=self.invoke(package,project);self.assertEqual(run.returncode,0,run.stdout+run.stderr)
            batch=(project/'scripts/Test-Batch.ps1').read_text();self.assertIn('$TimeoutSeconds = 7',batch);self.assertIn('$Concurrency = 12',batch);self.assertIn("'https://example.com/user-path?x=1&y=2'",batch)
            self.assertEqual((project/'nodes/unchanged.txt').read_bytes(),b'original node bytes\r\n');self.assertEqual((project/'batch-results-existing/sentinel').read_bytes(),b'existing report');self.assertEqual(len(list(project.glob('hotfix-backup-0.4.2-*'))),1)
    def test_child_failure_rolls_back_every_file(self):
        with tempfile.TemporaryDirectory() as td:
            package,project,manifest=self.fixture(td,fail=True);before={p.relative_to(project).as_posix():sha(p) for p in project.rglob('*') if p.is_file()};run=self.invoke(package,project);self.assertNotEqual(run.returncode,0)
            after={p.relative_to(project).as_posix():sha(p) for p in project.rglob('*') if p.is_file() and not p.relative_to(project).parts[0].startswith('hotfix-backup-')};self.assertEqual(before,after,run.stdout+run.stderr)
    def test_checksum_rejection_changes_nothing(self):
        with tempfile.TemporaryDirectory() as td:
            package,project,manifest=self.fixture(td);(package/'src/main.cpp').write_text('tampered');before={p.relative_to(project).as_posix():sha(p) for p in project.rglob('*') if p.is_file()};run=self.invoke(package,project);self.assertNotEqual(run.returncode,0);after={p.relative_to(project).as_posix():sha(p) for p in project.rglob('*') if p.is_file()};self.assertEqual(before,after)
if __name__=='__main__':unittest.main(verbosity=2)
