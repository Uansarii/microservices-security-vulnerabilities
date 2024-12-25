import pandas as pd
import json

df = pd.read_csv("trivy_vulns.csv")
df.reset_index()

vulns = []

for index, row in df.iterrows():
    if pd.isna(row.Date_added):
        d = ""
    else:
        d = row.Date_added

    if pd.isna(row.Severity):
        s = None
    else:
        s = row.Severity
    
    vulns.append({
        "code": row.Code,
        "name": row.Vulnerability,
        "date": d,
        "severity": s,
        "repetitions": row.Repetitions
    })

with open('trivy_vulns.json', 'w') as outfile:
    json.dump(vulns, outfile)