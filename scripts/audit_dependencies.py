"""Query the official PyPI release vulnerability feed; no TLS bypasses.

Fallback for this host's pip-audit Python HTTPS timeout. Not a complete CVE,
malware, source-code or supply-chain audit. Retains failures explicitly.
"""
import argparse
import concurrent.futures
import datetime
import json
from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[1]

def query(pin):
    name,version=pin.split('==')
    url=f'https://pypi.org/pypi/{name}/{version}/json'
    result=subprocess.run(['curl','--fail','--silent','--show-error','--max-time','30','--proto','=https',url],capture_output=True,text=True)
    if result.returncode:
        return {'name':name,'version':version,'url':url,'status':'failed','error':result.stderr.strip(),'vulnerabilities':None}
    try:
        data=json.loads(result.stdout)
        return {'name':name,'version':version,'url':url,'status':'checked','vulnerabilities':data['vulnerabilities']}
    except (ValueError,KeyError) as exc:
        return {'name':name,'version':version,'url':url,'status':'failed','error':str(exc),'vulnerabilities':None}

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--requirements',type=Path,default=ROOT/'requirements-dev.lock')
    parser.add_argument('--output',type=Path,default=ROOT/'evidence/dependency_audit.json')
    args=parser.parse_args()
    pins=[x.strip() for x in args.requirements.read_text().splitlines() if x.strip() and not x.startswith('#')]
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        results=list(pool.map(query,pins))
    report={'checked_at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'source':'Official PyPI per-release JSON vulnerability feed','requirements':args.requirements.name,
            'limitations':'Feed coverage only. Does not establish freedom from vulnerabilities; no independent penetration test.',
            'pip_audit_attempts':'Initial command used --disable-pip without -r (CLI error); corrected command timed out in Python HTTPS client. This verified-TLS curl fallback was run instead.',
            'packages':len(results),'checked':sum(x['status']=='checked' for x in results),
            'failed':sum(x['status']=='failed' for x in results),'advisories':sum(len(x['vulnerabilities'] or []) for x in results),'results':results}
    args.output.parent.mkdir(exist_ok=True,parents=True)
    args.output.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:report[k] for k in ['packages','checked','failed','advisories']}))
    return int(bool(report['failed'] or report['advisories']))

if __name__=='__main__':
    raise SystemExit(main())
