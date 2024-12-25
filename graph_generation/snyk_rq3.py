import pandas as pd
import json
import matplotlib.pyplot as plt

with open('snyk_project_sevs.json', "r") as json_file:
    project_sevs = json.load(json_file)

severity = range(4)
reps = []

for i in severity:
    reps.append(0)

for proj in project_sevs:
    reps[0] += project_sevs[proj]['low']
    reps[1] += project_sevs[proj]['medium']
    reps[2] += project_sevs[proj]['high']
    reps[3] += project_sevs[proj]['critical']

print(reps)

fig, ax = plt.subplots()
fig.set_tight_layout(True)
fig.set_size_inches(5.5, 4)

ax.set_xticks(range(4))
ax.set_xticklabels(['Low', 'Medium', 'High', 'Critical'])

plt.grid(color="#d4d7d9")
plt.plot(severity, reps, marker='o', color="#00b015")

plt.xlabel("Vulnerability severity")
plt.ylabel("Frequency")
plt.ylim([0, 7500])
plt.title("The Frequency of Each Severity of Vulnerability (Snyk)")
plt.savefig('graphs/rq3_snyk.pdf')