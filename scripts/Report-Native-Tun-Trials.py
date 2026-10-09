"""Produce reviewable evidence from the exact completed three-platform artifacts."""
import argparse,json,pathlib,statistics,subprocess
ROOT=pathlib.Path(__file__).resolve().parents[1]
def read(path):
    value=json.loads(path.read_text())
    if value.get('status')!='PASS':raise RuntimeError('Failed or incomplete evidence: '+str(path))
    return value
def main():
    p=argparse.ArgumentParser();p.add_argument('--artifacts',required=True,type=pathlib.Path);p.add_argument('--output',required=True,type=pathlib.Path);a=p.parse_args();a.output.mkdir(parents=True,exist_ok=True)
    sha=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
    report={'source_commit':sha,'stable_version':'0.4.11','stable_commit':'90a1853114de3e4bcb3deed6747801c10bc5b370','status':'PASS','scope':'Controlled TLS local fixtures, equal warmup/verified 8 MiB duplex echo; three rounds with rotated path order. Physical-device and production approval remain pending.','platforms':{},'performance_medians':[],'copy_microbenchmarks':[]}
    for platform in ('windows','linux','android'):
        base=a.artifacts/('native-tun-'+platform+'-'+sha);ev=base/'evidence'/platform
        perf=read(ev/'performance/performance-report.json');rows=perf['measurements']
        if len(rows)!=18:raise RuntimeError('Missing equivalent-load rounds: '+platform)
        device=read(ev/('android-device-report.json' if platform=='android' else 'device/device-report.json'))
        entry={'device':device,'performance_scope':perf['scope']}
        if platform!='android':
            entry['policy']=read(ev/'policy/policy-report.json')
            packet=read(ev/'packet/report.json');entry['packet']=packet
            for item in packet['tests']:
                if item.get('test')=='CPP_GO_COPY':report['copy_microbenchmarks'].append({'platform':platform,**item})
        for transport in ('raw','websocket'):
            for label in ('stable-proxy','candidate-proxy','candidate-native-tun'):
                group=[r for r in rows if r['transport']==transport and r['label']==label]
                if len(group)!=3 or any(r['status']!='PASS' or r['verified_payload_bytes']!=8388608 for r in group):raise RuntimeError('Missing verified load: '+platform)
                median={'platform':platform,'transport':transport,'path':label,'rounds':3}
                for field in ('goodput_mbit_s','rtt_ms_p50','rtt_ms_p95','rtt_ms_p99','cpu_seconds','rss_bytes','peak_rss_bytes','pss_bytes'):
                    if all(field in r for r in group):median[field]=statistics.median(r[field] for r in group)
                if label=='candidate-native-tun':
                    final=[]
                    for r in group:
                        data=r['native_abi_metrics_including_warmup']
                        if not data:raise RuntimeError('Missing final ABI counters')
                        final.append(data[-1])
                    median['native_final_counters']=final
                report['performance_medians'].append(median)
        report['platforms'][platform]=entry
    compatibility=read(a.artifacts/('native-tun-linux-'+sha)/'evidence/linux/stable-parser-comparison.json')
    if compatibility['rows']!=72767 or compatibility['changed_rows']!=0:raise RuntimeError('Parser regression')
    report['original_corpus_comparison']=compatibility
    report['remaining_acceptance']=['Physical Windows x64 and Android ARM phones','Live private 2,894-node regression with unchanged URIs/security/deadline','Physical IPv6 uplink and DNS leak/crash recovery captures','Long-duration reconnect/idle/Doze and resource/battery soak','Production security review and performance approval; no lwIP switch absent proven problem']
    (a.output/'native-tun-report.json').write_text(json.dumps(report,indent=2)+'\n')
    lines=['# Experimental Native TUN evidence','',f'Source: {sha}',f'CI run: https://github.com/noorelmostafa11-pixel/VPN-Core-Test/actions/runs/{__import__("os").environ.get("GITHUB_RUN_ID","")}', '',report['scope'],'','All 72,767 original inspection records and node IDs match stable 0.4.11. This checks the parser/config inventory, not live node connectivity.','','| Platform | Transport | Path | Mbit/s | RTT p50 ms | CPU s | RSS MiB |','|---|---|---|---:|---:|---:|---:|']
    for r in report['performance_medians']:lines.append(f"| {r['platform']} | {r['transport']} | {r['path']} | {r['goodput_mbit_s']:.2f} | {r['rtt_ms_p50']:.3f} | {r['cpu_seconds']:.3f} | {r['rss_bytes']/1048576:.2f} |")
    lines+=['','CPU covers the measured transfer and latency work; copies include warmup and both packet/payload crossings. RSS on desktop and Android PSS are different measures. The microbenchmark isolates ABI copy costs; throughput includes all tunnel work. Failures in final flow counters remain visible; an echo PASS does not assert every Android background-system flow succeeded.','','Actual OS TCP/UDP IPv4/IPv6 TLS raw/WebSocket, invalid certificate rejection on Android, desktop policy/recovery, and packet half-close/resource tests are recorded in the raw reports. Additional encrypted transport cases are in job logs. No private node corpus is published.','','## Physical acceptance still required','']+['- '+v for v in report['remaining_acceptance']]
    (a.output/'NATIVE-TUN-REPORT.md').write_text('\n'.join(lines)+'\n')
    print(json.dumps({'status':'PASS','source':sha,'performance_groups':len(report['performance_medians']),'unchanged_original_records':compatibility['rows']}))
if __name__=='__main__':main()
