import json

with open('proj_frequency.json', 'r') as f:
    projects = json.load(f)

vulns_key = {}

with open('vulns.csv') as f:
    for line in f:
        line = line.strip()
        parts = line.split(',')
        code = parts[1]
        name = parts[0]
        date = parts[2]
        sev = parts[3]
        vulns_key[code] = {"name": name, "date": date, "sev": sev}

project_vulns = {}

for proj in projects:
    vulns = []
    for code in projects[proj]:
        vulns.append({
            'name': vulns_key[code]["name"],
            'code': code,
            'date': vulns_key[code]["date"],
            'sev': vulns_key[code]["sev"],
            'reps': projects[proj][code]
        })
    project_vulns[proj] = vulns

with open('project_vulns.json', 'w') as f:
    json.dump(project_vulns, f)