from utilities import *

with open("repos_using.txt", "r") as repos_file:
    vulnerablities = {}
    for line in repos_file:
            url = line.strip()
            name = get_repo_name(url)
            with open("outputs/" + name + '.txt', "r") as output_file:
                for line in output_file:
                    if "CVE-" in line:
                        line = line.strip()
                        parts = line.split(" ")
                        for part in parts:
                            if "CVE-" in part and part[-1] != ')':
                                if part in vulnerablities:
                                    vulnerablities[part] += 1
                                    break
                                else:
                                    vulnerablities[part] = 1
                                    break
                    elif "https://avd.aquasec.com/misconfig/" in line:
                        line = line.strip()
                        parts = line.split("/")
                        code = parts[-1]
                        if code in vulnerablities:
                            vulnerablities[code] += 1
                        else:
                            vulnerablities[code] = 1

sorted_vulnerabilities_list = sorted(vulnerablities.items(), key=lambda vulns:vulns[1], reverse=True)
sorted_vulnerabilities = dict(sorted_vulnerabilities_list)

with open("frequency.csv", "w") as results_file:
    results_file.write("vulnerability,frequency\n")
    for vuln in sorted_vulnerabilities:
        results_file.write(vuln + "," + str(sorted_vulnerabilities[vuln]) + "\n")


