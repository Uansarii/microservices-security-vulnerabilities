import pandas as pd
import json
import matplotlib.pyplot as plt

with open('trivy_vulns.json', "r") as json_file:
    vulns = json.load(json_file)

severity = range(11)
reps = []

for i in severity:
    reps.append(0)

for vuln in vulns:
    if not pd.isna(vuln["severity"]):
        rep = vuln["repetitions"]
        sev = vuln["severity"]
        reps[round(sev)] += rep

fig, ax = plt.subplots()
fig.set_tight_layout(True)
fig.set_size_inches(5.5, 4)
plt.grid(color="#d4d7d9")
plt.plot(severity, reps, marker='o', color="#ff892e")

plt.xlabel("Vulnerability severity")
plt.ylabel("Frequency")
plt.title("The Frequency of Each Severity of Vulnerability (Trivy)")
plt.savefig('graphs/rq3_trivy.pdf')