import pandas as pd
import json
import matplotlib.pyplot as plt

with open('trivy_cwe_info.json', "r") as json_file:
    vulns = json.load(json_file)

years = {}

for i in range(2006, 2020):
    years[str(i)] = 0

for vuln in vulns:
    date = vuln["date"]
    if date != "":
        reps = vuln["reps"]
        year = date.split('-')[0]
        year = int(year)
        if year == 2020:
            print(vuln['code'])
        if str(year) in years:
            years[str(year)] += reps
        else:
            years[str(year)] = reps

years = dict(sorted(years.items()))

keys = years.keys()
values = years.values()

fig, ax = plt.subplots()
fig.set_tight_layout(True)
fig.set_size_inches(5.6, 4)
plt.xticks(rotation=90)
plt.grid(color="#d4d7d9")
plt.bar(keys, values, color="#ff892e", zorder=3)

print(years["2020"])

plt.xlabel("Year vulnerability type added to CWE")
plt.ylabel("Vulnerability count")
plt.title("Years detected vulnerability types were discovered (Trivy)")

plt.savefig("graphs/rq2_trivy_b.pdf")