"""Artifact cleanup previews, pagination, live-run and reference preservation."""
import datetime,importlib.util,io,json,os,pathlib,unittest,urllib.parse
from unittest.mock import patch
ROOT=pathlib.Path(__file__).resolve().parents[1]
class CleanupPolicyTests(unittest.TestCase):
    def test_preview_and_apply_preserve_active_runs_and_reference(self):
        spec=importlib.util.spec_from_file_location('cleanup',ROOT/'scripts/Cleanup-Artifacts.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        old=(datetime.datetime.now(datetime.timezone.utc)-datetime.timedelta(days=40)).isoformat();fresh=datetime.datetime.now(datetime.timezone.utc).isoformat()
        def artifact(number,name,created=old,sha='ordinary'):
            return {'id':number,'name':name,'created_at':created,'size_in_bytes':10,'workflow_run':{'id':number,'head_sha':sha}}
        items=[artifact(1,'core-linux'),artifact(2,'validation'),artifact(3,'active-core'),artifact(4,'reference',sha='reference'),artifact(5,'new-core',fresh)]
        for apply in (False,True):
            requests=[]
            def response(request,timeout):
                requests.append((request.full_url,request.get_method()));url=request.full_url
                if '/actions/artifacts?' in url:
                    page=int(urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)['page'][0]);data={'artifacts':items[:3] if page==1 else items[3:] if page==2 else []}
                elif '/actions/runs/' in url:data={'status':'in_progress' if url.endswith('/3') else 'completed'}
                elif request.get_method()=='DELETE':data={}
                else:raise AssertionError('Unexpected endpoint '+url)
                return io.BytesIO(json.dumps(data).encode())
            args=['cleanup','--repository','fixture/core','--protect-core-sha','reference']+(['--apply'] if apply else [])
            with patch.dict(os.environ,{'GH_TOKEN':'synthetic-test-token'}),patch('sys.argv',args),patch('urllib.request.urlopen',response),patch('sys.stdout',new_callable=io.StringIO) as output:module.main()
            self.assertEqual(json.loads(output.getvalue())['artifacts'],2)
            deletions=[url for url,method in requests if method=='DELETE'];self.assertEqual(deletions,[f'https://api.github.com/repos/fixture/core/actions/artifacts/{i}' for i in (1,2)] if apply else [])
            if apply:
                last_page=next(i for i,v in enumerate(requests) if '&page=3' in v[0]);self.assertTrue(all(i>last_page for i,v in enumerate(requests) if v[1]=='DELETE'))
