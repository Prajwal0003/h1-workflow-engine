import json
import collections

file_path = r'C:\Users\prajw\Downloads\latest-bounty-results-120013\data\autopilot\latest_fast_scan.json'

with open(file_path, 'r', encoding='utf-8') as f:
    data = json.load(f)

crits = [x for x in data if x.get('severity') in ['CRITICAL', 'HIGH']]

grouped = collections.defaultdict(list)
for x in crits:
    grouped[x['type']].append(x)

for typ, items in grouped.items():
    print(f"\n=== {typ} ({len(items)} findings) ===")
    for x in items[:5]: # Print up to 5 examples per type
        detail = x.get('detail', '').encode('ascii', 'ignore').decode('ascii')
        print(f"  [{x['severity']}] {x['url']}")
        print(f"    -> {detail[:150]}")
    if len(items) > 5:
        print(f"  ... and {len(items)-5} more.")
