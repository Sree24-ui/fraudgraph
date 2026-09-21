"""Submit a real NDJSON transaction stream with durable, idempotent acknowledgments.

Each line must match the transaction schema, including truthful provenance.
Passwords are prompted, never command-line arguments. IDs must survive retries.
"""
import argparse
import getpass
import json
import sys
import time
from urllib.parse import urlparse
import httpx

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--url',required=True)
    parser.add_argument('--username',required=True)
    parser.add_argument('--file',default='-',help='NDJSON file, or - for stdin')
    args=parser.parse_args()
    parsed=urlparse(args.url)
    if parsed.scheme!='https' and not(parsed.scheme=='http' and parsed.hostname in {'localhost','127.0.0.1','::1'}):
        parser.error('Use HTTPS except for loopback development')
    if parsed.path not in {'','/'} or parsed.query or parsed.fragment or parsed.username:
        parser.error('URL must be an origin only')
    origin=args.url.rstrip('/')
    password=getpass.getpass('Password: ')
    stream=sys.stdin if args.file=='-' else open(args.file,encoding='utf-8')
    try:
        with httpx.Client(base_url=origin,timeout=30,headers={'Origin':origin}) as client:
            response=client.post('/api/login',json={'username':args.username,'password':password})
            response.raise_for_status()
            client.headers['X-CSRF-Token']=response.json()['csrf']
            try:
                for line_number,line in enumerate(stream,1):
                    if not line.strip():continue
                    event=json.loads(line)
                    # Commit one event at a time. Re-running an interrupted file
                    # is safe when original IDs and payloads are unchanged.
                    for attempt in range(4):
                        try:
                            response=client.post('/api/transactions/batch',json={'transactions':[event]})
                            if response.status_code==503 and attempt<3:
                                time.sleep(2**attempt);continue
                            response.raise_for_status()
                            break
                        except httpx.TransportError:
                            if attempt==3:raise
                            time.sleep(2**attempt)
                    print(json.dumps({'line':line_number,**response.json()}),flush=True)
            finally:
                client.post('/api/logout')
    finally:
        if stream is not sys.stdin:stream.close()

if __name__=='__main__':
    main()
