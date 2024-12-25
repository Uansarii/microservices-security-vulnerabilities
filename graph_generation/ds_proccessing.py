import pandas as pd
import json

df = pd.read_csv("ds_vulns.csv")
df.reset_index()

vulns = []

for index, row in df.iterrows():
    if pd.isna(row.Date):
        d = ""
    else:
        d = row.Date
    
    vulns.append({
        "code": row.Code,
        "name": row.Vulnerability,
        "date": d,
        "repetitions": row.Repetitions
    })

with open('ds_vulns.json', 'w') as outfile:
    json.dump(vulns, outfile)