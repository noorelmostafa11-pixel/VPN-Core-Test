"""DNS wire boundaries and TCP retry without adapter or network changes."""
import json, os, pathlib, shutil, subprocess, tempfile, unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
class NativeDnsTests(unittest.TestCase):
    def test_wire_boundaries_truncation_and_partial_tcp_close(self):
        compiler=shutil.which('g++')
        self.assertIsNotNone(compiler,'C++ compiler required for DNS boundary test')
        with tempfile.TemporaryDirectory(prefix='vpn-dns-boundaries-') as directory:
            binary=pathlib.Path(directory)/('dns-probe.exe' if os.name=='nt' else 'dns-probe')
            flags=['-std=c++17','-O2','-Wall','-Wextra','-Werror','-Wno-misleading-indentation']
            libraries=['-pthread']
            if os.name=='nt':
                flags+=['-D_WIN32_WINNT=0x0A00','-static','-static-libgcc','-static-libstdc++']
                libraries+=['-lws2_32','-lsecur32','-lcrypt32','-lbcrypt']
            else:flags+=['-DVPN_CORE_PORTABLE'];libraries+=['-ldl']
            subprocess.run([compiler,*flags,str(ROOT/'tests/native_dns_probe.cpp'),'-o',str(binary),*libraries],check=True,timeout=120)
            result=subprocess.run([str(binary)],capture_output=True,text=True,timeout=10)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            row=json.loads(result.stdout)
            self.assertEqual(row['status'],'PASS');self.assertFalse(row['network_io'])
if __name__=='__main__':unittest.main()
