import pandas as pd
import json
import matplotlib.pyplot as plt

with open('trivy_vulns.json', "r") as json_file:
    vulns = json.load(json_file)


codes = []
reps = []

for vuln in vulns[:10]:
    codes.append(vuln["code"])
    reps.append(vuln["repetitions"])


fig, ax = plt.subplots()
plt.xticks(rotation=90)
fig.set_tight_layout(True)
fig.set_size_inches(6, 5)
plt.bar(codes, reps, color="#ff892e", zorder=3)
plt.grid()
plt.xlabel("Vulnerability code")
plt.ylabel("Repetitions of vulnerability")
plt.title("Top 10 Most Common Vulnerabilities (Trivy)")
plt.savefig('graphs/rq1_trivy.png')