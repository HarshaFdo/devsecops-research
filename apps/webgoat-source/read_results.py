import json

with open('semgrep_webgoat_run2.json', 'r', encoding='utf-8-sig') as f:
    data = json.load(f)

results = data.get('results', [])
print(f'Total findings: {len(results)}')