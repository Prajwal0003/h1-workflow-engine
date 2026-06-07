import json

review_path = r'C:\Users\prajw\Downloads\latest-bounty-results-130602\data\autopilot\needs_review.json'

with open(review_path, 'r', encoding='utf-8') as f:
    review = json.load(f)

print("=== FINDINGS THAT NEED MANUAL REVIEW ===")
real_candidates = []
for x in review:
    if x.get('severity') in ['CRITICAL', 'HIGH']:
        triage = x.get('ai_triage', {})
        verdict = triage.get('verdict')
        # If the AI explicitly says it's a false positive, we trust it.
        # But if the AI says 'NEEDS_REVIEW', we should look at it!
        if verdict == 'NEEDS_REVIEW':
            real_candidates.append(x)

if not real_candidates:
    print("None! The AI confidently marked all of them as FALSE_POSITIVE.")
else:
    print(f"Found {len(real_candidates)} findings the AI was unsure about:\n")
    for x in real_candidates[:10]:
        reason = x.get('ai_triage', {}).get('reasoning', '').encode('ascii', 'ignore').decode('ascii')
        detail = x.get('detail', '').encode('ascii', 'ignore').decode('ascii')
        print(f"[{x['severity']}] {x['type']} on {x['url']}")
        print(f"  AI Reason: {reason}")
        print(f"  Scanner Detail: {detail[:100]}...\n")
        
    if len(real_candidates) > 10:
        print(f"... and {len(real_candidates)-10} more.")
