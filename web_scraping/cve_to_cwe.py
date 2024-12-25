import bs4 as bs
import urllib.request
import json

codes = {}

with open("vulns.csv", "r") as vulns_file:
    for line in vulns_file:
        line = line.strip()
        parts = line.split(",")
        code = parts[1]
        
        print("\n" + code)

        if code.startswith("CVE") and code != "CVE-2016-1000227":
            reps = int(parts[-1])
            source = urllib.request.urlopen('https://nvd.nist.gov/vuln/detail/' + code).read()

            soup = bs.BeautifulSoup(source, 'lxml')

            table_row = soup.find_all("td", attrs={'data-testid': "vuln-CWEs-link-0"})

            cwe_code_element = table_row[0]
            cwe_code = cwe_code_element.text.strip()

            if cwe_code in codes:
                codes[cwe_code] += reps
            else:
                codes[cwe_code] = reps

            print (code + " -> " + cwe_code)

with open('cwe_codes.json', 'w') as outfile:
    json.dump(codes, outfile)
