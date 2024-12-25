from utilities import *
import json

with open("repos_using.txt", "r") as repos_file:
    projects = {}
    for line in repos_file:
        url = line.strip()
        name = get_repo_name(url)
        vulnerablities = {}
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
        projects[name] = vulnerablities

with open("proj_frequency.json", "w") as results_file:
    json.dump(projects, results_file)


