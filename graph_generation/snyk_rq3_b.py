import json
import matplotlib.pyplot as plt
import numpy as np
import copy

with open("snyk_project_sevs.json", "r") as f:
    proj_vulns = json.load(f)

reps = []

proj_vulns = dict(sorted(proj_vulns.items(), key=lambda i: i[0].lower()))



for proj in proj_vulns:
    reps2 = [proj_vulns[proj]['critical'], proj_vulns[proj]['high'], proj_vulns[proj]['medium'], proj_vulns[proj]['low']]
    reps.append(reps2)


reps = np.array(reps)
reps = np.transpose(reps)

fig, ax = plt.subplots()
im = ax.imshow(reps)

project_titles = proj_vulns.keys()

ax.set_xticks(np.arange(len(project_titles)))
ax.set_yticks(range(4))

x_labels = []

for i in range(30):
    x_labels.append("P" + str(i + 1))

ax.set_xticklabels(x_labels)
ax.set_yticklabels(['Critical', 'High', 'Medium', 'Low'])

for i in range(4):
    for j in range(len(project_titles)):
        text = ax.text(j, i, reps[i, j],
                       ha="center", va="center", color="w")

plt.xlabel("Project identifier")
plt.ylabel("Vulnerability severity")
plt.title("Vulnerability Severity Frequency Within Each Project (Snyk)")

fig.tight_layout()
fig.set_size_inches(13, 4)
plt.savefig('graphs/rq3_snyk_b.pdf')