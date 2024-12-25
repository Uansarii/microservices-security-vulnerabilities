import pandas as pd
import json
import matplotlib.pyplot as plt

with open('snyk_vulns.json', "r") as json_file:
    vulns = json.load(json_file)

years = {}

for i in range(2006, 2021):
    years[str(i)] = 0

for vuln in vulns:
    date = vuln["date"]
    if date != "":
        reps = vuln["reps"]
        year = date.split('-')[0]
        year = int(year)
        if str(year) in years:
            years[str(year)] += reps
        else:
            years[str(year)] = reps

years = dict(sorted(years.items()))

fig, ax = plt.subplots()
fig.set_tight_layout(True)
fig.set_size_inches(6.4, 4.5)
plt.xticks(rotation=90)
plt.grid(color="#d4d7d9")
plt.bar(years.keys(), years.values(), color="#00b015", zorder=3)

plt.xlabel("Year vulnerability type added to CWE")
plt.ylabel("Vulnerability count")
plt.title("Years detected vulnerability types were discovered (Snyk)")
plt.savefig("graphs/rq2_snyk.pdf")