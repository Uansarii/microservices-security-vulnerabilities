from utilities import *

url = "https://github.com/dotnet-architecture/eShopOnContainers"

name = get_repo_name(url)

generate_output(url, "outputs")

print(name + ": " + str(count_vulns(name, "outputs")))