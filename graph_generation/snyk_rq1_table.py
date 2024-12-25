import json
from operator import itemgetter

with open('snyk_vulns.json', 'r') as f:
    vulns = json.load(f)

vulns = sorted(vulns, key=itemgetter('reps'), reverse=True)

for vuln in vulns[:10]:
    print(vuln['name'] + ' & ' + vuln['code'] + ' & ' + vuln['date'] + ' & ' + str(vuln['reps']) + " \\" + "\\")
    print('\\hline')