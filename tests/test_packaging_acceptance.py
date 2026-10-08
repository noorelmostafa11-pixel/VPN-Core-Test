"""Corrupted runtime and license/provenance rejection with synthetic artifacts."""
import hashlib,importlib.util,json,os,pathlib,shutil,subprocess,sys,tempfile,unittest,zipfile
ROOT=pathlib.Path(__file__).resolve().parents[1]
class PackagingAcceptanceTests(unittest.TestCase):
    def fixture(self,folder):
        data=b'synthetic runtime bytes';(folder/'vpn-core').write_bytes(data)
        files=[{'file':'vpn-core','bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}]
        (folder/'build-hashes.json').write_text(json.dumps(files));(folder/'build-provenance.json').write_text(json.dumps({'version':'synthetic','target':'linux-amd64','files':files}))
    def test_corrupt_byte_is_rejected_before_packaging(self):
        with tempfile.TemporaryDirectory() as td:
            folder=pathlib.Path(td);self.fixture(folder)
            good=subprocess.run([sys.executable,ROOT/'scripts/Verify-Target.py',folder],capture_output=True,text=True);self.assertEqual(good.returncode,0,good.stderr)
            (folder/'vpn-core').write_bytes(b'corrupted runtime bytes')
            bad=subprocess.run([sys.executable,ROOT/'scripts/Package-Target.py','--build',folder,'--output',folder/'out'],capture_output=True,text=True)
            self.assertNotEqual(bad.returncode,0);self.assertFalse((folder/'out').exists())
    def test_provenance_manifest_mismatch_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            folder=pathlib.Path(td);self.fixture(folder);meta=json.loads((folder/'build-provenance.json').read_text());meta['files']=[];(folder/'build-provenance.json').write_text(json.dumps(meta))
            result=subprocess.run([sys.executable,ROOT/'scripts/Verify-Target.py',folder],capture_output=True,text=True);self.assertNotEqual(result.returncode,0);self.assertIn('Manifest/provenance',result.stdout+result.stderr)
    def test_android_notice_is_required_before_packaging(self):
        spec=importlib.util.spec_from_file_location('android_package',ROOT/'scripts/Package-Android.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as td:
            folder=pathlib.Path(td)
            with self.assertRaises(FileNotFoundError):module.package([('arm64-v8a',folder)],folder/'out.aar','synthetic')
    def test_aar_contains_notice_provenance_and_compiled_java_binding(self):
        javac=str(pathlib.Path(os.environ['JAVA_HOME'])/'bin/javac') if os.environ.get('JAVA_HOME') else shutil.which('javac')
        if not javac:self.skipTest('JDK required for AAR packaging fixture')
        spec=importlib.util.spec_from_file_location('android_package',ROOT/'scripts/Package-Android.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as td:
            folder=pathlib.Path(td);notice=b'Synthetic NDK notice for packaging test only';(folder/'NDK-NOTICE.txt').write_bytes(notice)
            for name in ['libvpn-core.so','libvpn-tls.so','libvpn-jni.so']:(folder/name).write_bytes(b'synthetic native fixture '+name.encode())
            provenance={'commit':'synthetic-source','source_files_sha256':'synthetic-fingerprint','dirty':False}
            package=module.package([('arm64-v8a',folder)],folder/'out.aar','synthetic',javac,provenance=provenance)
            with zipfile.ZipFile(package) as aar:
                self.assertEqual(aar.read('META-INF/vpn-core/NDK-NOTICE.txt'),notice);sdk=json.loads(aar.read('assets/vpn-core/sdk.json'));self.assertEqual(sdk['source'],provenance)
                with zipfile.ZipFile(__import__('io').BytesIO(aar.read('classes.jar'))) as jar:self.assertIn('com/noorelmostafa/vpncore/NativeCore.class',jar.namelist())
                self.assertEqual(sdk['native_files'][0]['sha256'],hashlib.sha256(aar.read('jni/arm64-v8a/libvpn-core.so')).hexdigest())
