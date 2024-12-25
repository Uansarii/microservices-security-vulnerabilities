import json
import bs4 as bs
import urllib.request

with open("trivy_cwe_codes.json", "r") as f:
    codes = json.load(f)

vuln_info = []

for code in codes:
    print(code)
    if code.startswith("CWE"):
        vuln = {}
        number = code.split('-')[1]

        source = urllib.request.urlopen('https://cwe.mitre.org/data/definitions/' + number + '.html').read()

        soup = bs.BeautifulSoup(source, 'lxml')

        title = soup.find('h2')
        vuln["code"] = code
        vuln["name"] = title.text.split(': ')[1]

        info_table = soup.find("tbody", id = "oc_" + number + "_Submissions")
        vuln["date"] = info_table.findChildren("tr")[1].findChildren("td")[0].text

        vuln["reps"] = codes[code]
        
        vuln_info.append(vuln)

print(vuln_info)

with open("trivy_cwe_info.json", "w") as output_file:
    json.dump(vuln_info, output_file)