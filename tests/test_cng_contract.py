"""Exercise the Windows RNG branch against a strict CNG contract double.

This host test does not replace executing the production DLL on Windows.
"""
import os,pathlib,subprocess,tempfile,unittest
from test_core import ROOT

@unittest.skipIf(os.name=='nt','Windows executes the real CNG UDP cipher matrix')
class CngContractTests(unittest.TestCase):
    def test_zero_iv_does_not_call_rng_and_failures_are_preserved(self):
        with tempfile.TemporaryDirectory() as td:
            probe=pathlib.Path(td)/'cng-contract'
            subprocess.run(['g++','-std=c++17','-O1','-Wall','-Wextra','-Wpedantic','-Werror',
                '-Wno-misleading-indentation',str(ROOT/'tests/cng_lifetime_probe.cpp'),'-o',str(probe),
                '-lssl','-lcrypto','-pthread'],check=True,capture_output=True,text=True)
            result=subprocess.run([str(probe),'rng'],capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            self.assertIn('empty IV bypasses CNG',result.stdout)
