"""Preview or delete expired Actions artifacts; preserve active runs and releases."""
import argparse,datetime,json,os,urllib.request

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--repository',required=True);p.add_argument('--apply',action='store_true');p.add_argument('--runtime-days',type=int,default=1);p.add_argument('--report-days',type=int,default=30);p.add_argument('--protect-core-sha',action='append',default=[]);a=p.parse_args()
    if a.runtime_days<1 or a.report_days<1:p.error('Retention must be at least one day')
    token=os.environ['GH_TOKEN'];base='https://api.github.com/repos/'+a.repository
    def api(path,method='GET'):
        req=urllib.request.Request(base+path,method=method,headers={'Authorization':'Bearer '+token,'Accept':'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28'})
        with urllib.request.urlopen(req,timeout=30) as response:return json.load(response) if method=='GET' else None
    now=datetime.datetime.now(datetime.timezone.utc);runs={};candidates=[];page=1
    while True:
        items=api('/actions/artifacts?per_page=100&page='+str(page))['artifacts']
        if not items:break
        for item in items:
            run=item.get('workflow_run',{});rid=run.get('id')
            if not rid or run.get('head_sha') in a.protect_core_sha:continue
            if rid not in runs:runs[rid]=api('/actions/runs/'+str(rid))['status']
            if runs[rid]!='completed':continue
            report=any(term in item['name'] for term in ('validation','results','comparison','report','support'))
            days=a.report_days if report else a.runtime_days
            age=now-datetime.datetime.fromisoformat(item['created_at'].replace('Z','+00:00'))
            if age>=datetime.timedelta(days=days):candidates.append(item)
        page+=1
    # Enumerate every page before mutation; deleting during pagination skips items.
    for item in candidates:
        if a.apply:api('/actions/artifacts/'+str(item['id']),'DELETE')
    print(json.dumps({'mode':'APPLIED' if a.apply else 'PREVIEW','artifacts':len(candidates),'bytes':sum(v['size_in_bytes'] for v in candidates),'release_assets':'PRESERVED','protected_commits':a.protect_core_sha}))
if __name__=='__main__':main()
