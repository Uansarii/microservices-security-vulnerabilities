import json
import matplotlib.pyplot as plt
import numpy as np
import copy

with open("project_vulns.json", "r") as f:
    proj_vulns = json.load(f)


proj_vulns = dict(sorted(proj_vulns.items(), key=lambda i: i[0].lower()))

sevs = range(11)[::-1]
reps = []



for proj in proj_vulns:
    reps2 = [0] * 11
    for vuln in proj_vulns[proj]:
        sev = vuln['sev']
        if sev != '':
            sev = float(sev)
            reps2[round(sev)] += vuln["reps"]
    print(reps2)
    reps.append(reps2)


reps = np.array(reps)
reps = np.transpose(reps)
reps = np.flip(reps, axis=0)

fig, ax = plt.subplots()
im = ax.imshow(reps)

project_titles = proj_vulns.keys()

# plt.xticks(rotation=90)

ax.set_xticks(np.arange(len(project_titles)))
ax.set_yticks(range(11))

x_labels = []

for i in range(30):
    x_labels.append("P" + str(i + 1))

ax.set_xticklabels(x_labels)
ax.set_yticklabels(sevs)

for i in range(11):
    for j in range(len(project_titles)):
        text = ax.text(j, i, reps[i, j],
                       ha="center", va="center", color="w")

plt.xlabel("Project identifier")
plt.ylabel("Vulnerability severity")
plt.title("Vulnerability Severity Frequency Within Each Project (Trivy)")

fig.tight_layout()
fig.set_size_inches(12, 5)
plt.savefig('graphs/rq3_trivy_b.pdf')