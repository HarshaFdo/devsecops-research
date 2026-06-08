import json

with open('trivy_webgoat_run1.json', 'r', encoding='utf-8') as f:
    data = json.load(f)

results = data.get('Results', [])
total = 0
for r in results:
    vulns = r.get('Vulnerabilities', [])
    total += len(vulns)
    if vulns:
        target = r['Target']
        print(f'Target: {target}')
        print(f'Vulnerabilities: {len(vulns)}')
print(f'Total: {total}')