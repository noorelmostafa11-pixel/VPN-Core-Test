"""Linux host failure/recovery decisions; no actual routes or nft mutations."""
import json,os,pathlib,sys,unittest
from unittest.mock import Mock,mock_open,patch
ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'sdk/linux'),str(ROOT/'sdk/native')]
@unittest.skipIf(os.name=='nt','Linux policy transaction tests')
class LinuxPolicyLifecycleTests(unittest.TestCase):
    def test_rule_comment_cannot_authorize_deleting_unowned_table(self):
        import native_tun as native
        for document in (
            {'nftables':[{'table':{'family':'inet','name':native.TABLE,'comment':'another-owner'}},{'rule':{'comment':native.COMMENT}}]},
            {'nftables':[{'table':{'family':'ip','name':native.TABLE,'comment':native.COMMENT}}]},
            {'nftables':[{'table':{'family':'inet','name':'another-table','comment':native.COMMENT}}]},
        ):
            with self.subTest(document=document),patch.object(native.subprocess,'run',return_value=Mock(returncode=0,stdout=json.dumps(document))),patch.object(native,'command') as command:
                with self.assertRaisesRegex(RuntimeError,'unowned'):native.LinuxPolicy.recover()
                command.assert_not_called()
    def test_owned_table_recovery_deletes_only_exact_table(self):
        import native_tun as native
        doc={'nftables':[{'table':{'family':'inet','name':native.TABLE,'comment':native.COMMENT}}]}
        with patch.object(native.subprocess,'run',return_value=Mock(returncode=0,stdout=json.dumps(doc))),patch.object(native,'command') as command:
            native.LinuxPolicy.recover();command.assert_called_once_with('nft','delete','table','inet',native.TABLE)
    def test_recovery_inspection_failure_is_not_reported_as_success(self):
        import native_tun as native
        with patch.object(native.subprocess,'run',return_value=Mock(returncode=1,stderr='Operation not permitted')),patch.object(native,'command') as command:
            with self.assertRaisesRegex(RuntimeError,'retained'):native.LinuxPolicy.recover()
            command.assert_not_called()
    def test_missing_table_recovery_is_idempotent(self):
        import native_tun as native
        with patch.object(native.subprocess,'run',return_value=Mock(returncode=1,stderr='No such file or directory')),patch.object(native,'command') as command:
            native.LinuxPolicy.recover();command.assert_not_called()
    def exercise_host(self,*,configuration_error=None,core_result=0):
        import native_tun as native
        host=Mock(result=core_result);host.bootstrap_targets.return_value=[{'host':'fixture.invalid','port':443}];host.thread.is_alive.return_value=False;host.stop.return_value=core_result
        policy=Mock(acquired=True)
        if configuration_error:policy.configure.side_effect=configuration_error
        args=['native_tun.py','--build','/tmp/fixture-build','--config','/tmp/fixture-config','--node-host','fixture.invalid','--node-port','443','--uplink','fixture0']
        with patch.object(sys,'argv',args),patch.object(native.os,'geteuid',return_value=0),patch('builtins.open',mock_open()),patch.object(native.fcntl,'flock'),patch.object(native.socket,'if_nametoindex',return_value=1),patch.object(native.socket,'getaddrinfo',return_value=[(2,1,6,'',('192.0.2.9',443))]),patch.object(native,'TunHost',return_value=host),patch.object(native,'LinuxPolicy',return_value=policy),patch.object(native.signal,'signal'):
            if configuration_error:
                with self.assertRaisesRegex(RuntimeError,'DNS setup'):native.main()
            else:native.main()
        host.stop.assert_called_once()
        return policy
    def test_failed_network_configuration_keeps_guard_after_clean_core_stop(self):
        self.exercise_host(configuration_error=RuntimeError('DNS setup failed')).close.assert_not_called()
    def test_core_failure_keeps_guard(self):
        self.exercise_host(core_result=1).close.assert_not_called()
    def test_clean_disconnect_releases_owned_guard(self):
        self.exercise_host().close.assert_called_once()
if __name__=='__main__':unittest.main()
