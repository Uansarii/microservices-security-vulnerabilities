from utilities import *

with open("results.csv", "w") as results_file:
    results_file.write("repo,vulnerabilities\n")
    with open("repos.txt", "r") as repos_file:
        for line in repos_file:
            repo_url = line.strip()
            name = get_repo_name(repo_url)
            results_file.write(name + ",")
            generate_output(repo_url, "outputs")

            vulns = count_vulns(name, "outputs")

            results_file.write(str(vulns) + "\n")

