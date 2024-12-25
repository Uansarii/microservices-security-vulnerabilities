from utilities import *

with open("categories.csv", "w") as results_file:
    results_file.write("name,dependency vulnerabilities,configuration vulnerabilities\n")

    with open("monolithic.txt", "r") as repos_file:
        for line in repos_file:
            url = line.strip()
            name = get_repo_name(url)
            
            results_file.write(name + ",")

            generate_output(url, "mono_outputs")

            dep = count_dep(name, "mono_outputs")
            cont = count_cont(name, "mono_outputs")


            results_file.write(str(dep) + "," + str(cont) + "\n")

    with open("repos.txt", "r") as repos_file:
        for line in repos_file:
            url = line.strip()
            name = get_repo_name(url)
            
            results_file.write(name + ",")

            generate_output(url, "outputs")

            dep = count_dep(name, "outputs")
            cont = count_cont(name, "outputs")


            results_file.write(str(dep) + "," + str(cont) + "\n")

    

