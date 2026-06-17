import json

with open('semgrep_run1.json', 'r', encoding='utf-8-sig') as f:
    data = json.load(f)

results = data.get('results', [])
print(f'Total findings: {len(results)}')
for r in results:
    rule = r.get('check_id', '')
    line = r.get('start', {}).get('line', '')
    msg = r.get('extra', {}).get('message', '')[:60]
    severity = r.get('extra', {}).get('severity', '')
    rule_short = rule.split('.')[-1]
    print(f'  Line {line} [{severity}] {rule_short}: {msg}')