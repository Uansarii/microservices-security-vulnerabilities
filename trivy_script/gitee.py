from utilities import *

urls = ["https://gitee.com/su-aiya/susu713", "https://gitee.com/zx_l/grocery-micro-service"]

for url in urls:
    name = get_repo_name(url)

    generate_output(url, "outputs")

    print(name + ": " + str(count_vulns(name, "outputs")))