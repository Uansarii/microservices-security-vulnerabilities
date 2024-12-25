import pandas as pd
import json

df = pd.read_csv("snyk_severity.csv")
df.reset_index()

projects = {}

for index, row in df.iterrows():
    projects[row.project] = {
        "critical": row.critical,
        "high": row.high,
        "medium": row.medium,
        "low": row.low
    }

with open('sny_project_sevs.json', 'w') as outfile:
    json.dump(projects, outfile)