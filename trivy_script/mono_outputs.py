from utilities import *

with open("monolithic.txt", "r") as repos_file:
    for line in repos_file:
        url = line.strip()
        generate_output(url, "mono_outputs")
        name = get_repo_name(url)
        print(name + ": " + str(count_vulns(name, "mono_outputs")))