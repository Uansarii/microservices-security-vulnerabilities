from utilities import *

x = 0

total = 0

vulns = {}

with open("frequency.csv", "r") as f:
    for line in f:
        if x == 0:
            x = 63275
            continue
        line = line.strip()
        parts = line.split(',')

        if 'CVE' in parts[0]:
            vulns[parts[0]] = [int(parts[1])]
            total += int(parts[1])

update_lib = 0
other = 0

updates = []
others = []


for code in vulns:
    with open("repos_using.txt", "r") as f:
        for line in f:
            url = line.strip()
            name = get_repo_name(url)
            with open('outputs/' + name + '.txt', "r") as output_f:
                for line in output_f:
                    line = line.strip()
                    if code in line:
                        parts = line.split('│')
                        f_ver = parts[5]
                        if not f_ver.isspace():
                            update_lib += vulns[code][0]
                            updates.append({code: vulns[code][0]})
                            vulns[code].append('update library')
                            break
                        else:
                            other += vulns[code][0]
                            others.append({code: vulns[code][0]})
                            vulns[code].append('other')
                            break
            if len(vulns[code]) > 1:
                break

print(others)
                    
print(update_lib)
print(other)
print(total)
print(update_lib / total)

