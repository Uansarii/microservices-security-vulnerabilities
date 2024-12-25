import os

def generate_output(url, folder):
    file_name = get_repo_name(url) + ".txt"
    os.system("trivy repo --scanners vuln,config,secret " + url + " > " + folder + "/" + file_name)

def get_repo_name(url):
    parts = url.split('/')
    return parts[-1]
    
def count_vulns(n, folder):
    v = 0

    with open(folder + "/" + n + ".txt", "r") as output_file:
        for l in output_file:
            if "Total:" in l or "Failures:" in l:
                l.strip()
                words = l.split()
                v += int(words[1])

    return v

def count_dep(n, folder):
    v = 0

    with open(folder + "/" + n + ".txt", "r") as output_file:
        for l in output_file:
            if "Total:" in l:
                l.strip()
                words = l.split()
                v += int(words[1])

    return v


def count_cont(n, folder):
    v = 0

    with open(folder + "/" + n + ".txt", "r") as output_file:
        for l in output_file:
            if "Failures:" in l:
                l.strip()
                words = l.split()
                v += int(words[1])

    return v