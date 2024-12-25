from utilities import *
import random

x = 0

total = 0

vulns = {}

sample_size = 310

with open("frequency.csv", "r") as f:
    for line in f:
        if x == 0:
            x = 63275
            continue
        line = line.strip()
        parts = line.split(',')

        if not 'CVE' in parts[0]:
            vulns[parts[0]] = [int(parts[1])]
            total += int(parts[1])

print(total)

sum = 0
sample = []

while sum < sample_size:
    code = random.choice(list(vulns.keys()))

    sample.append({code: vulns[code]})
    sum += vulns[code][0]

    vulns.pop(code)

print(sample)