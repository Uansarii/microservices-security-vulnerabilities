import pandas as pd
import json
import matplotlib.pyplot as plt

with open('ds_vulns.json', "r") as json_file:
    vulns = json.load(json_file)

codes = []
reps = []

x = 0

for vuln in vulns:
    if x < 10 and vuln["code"].startswith('CWE'):
        codes.append(vuln["code"])
        reps.append(vuln["repetitions"])
        x += 1
    if x == 10:
        break


fig, ax = plt.subplots()
plt.xticks(rotation=90)
fig.set_tight_layout(True)
fig.set_size_inches(6,5)
plt.bar(codes, reps, color="#316ccc", zorder=3)
plt.grid(color="#d4d7d9")
plt.xlabel("Vulnerability code")
plt.ylabel("Repetitions of vulnerability")
plt.title("Top 10 Most Common Vulnerability Types (DeepSource)")
plt.savefig("graphs/rq1_ds.pdf")