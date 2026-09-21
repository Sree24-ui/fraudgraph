"""Write explicitly SYNTHETIC transactions to NDJSON for the stream client."""
import argparse
import json
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from fraudgraph.synthetic import generate_scenario,SCENARIOS

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--scenario',choices=SCENARIOS,default='fan_in_fan_out')
parser.add_argument('--seed',type=int,default=7)
args=parser.parse_args()
print('SYNTHETIC fixture; not real UPI data or a real-world accuracy estimate.',file=sys.stderr)
for transaction in generate_scenario(args.scenario,seed=args.seed)['transactions']:
    print(json.dumps(transaction))
