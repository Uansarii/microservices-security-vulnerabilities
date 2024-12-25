import bs4 as bs
import urllib.request
import json

with open("snyk_codes.json", "r") as f:
    vulns = json.load(f)

print(vulns)

snyk_vulns = []

deepsource_vulns = {}

with open('deepsource_vulns.csv', 'r') as deepsource_file:
    for line in deepsource_file:
        line = line.strip()
        parts = line.split(',')
        code = parts[1]\
        
        if code.startswith('CWE'):
            deepsource_vulns[code] = {
                'name': parts[0],
                'date': parts[2]
            }


with open('snyk_vulns.json', "w") as output_file:
    for number in vulns:
        print(number)
        code = 'CWE-' + number

        if code in deepsource_vulns:
            print('Found\n')
            snyk_vulns.append({
                'name': deepsource_vulns[code]['name'],
                'code': code,
                'date': deepsource_vulns[code]['date'],
                'reps': vulns[number]
            })
        else:
            print('Scraping\n')
            source = urllib.request.urlopen('https://cwe.mitre.org/data/definitions/' + number + '.html').read()

            soup = bs.BeautifulSoup(source, 'lxml')

            title = soup.find('h2')
            name = title.text.split(': ')[1]

            info_table = soup.find("tbody", id = "oc_" + number + "_Submissions")
            date = info_table.findChildren("tr")[1].findChildren("td")[0].text

            snyk_vulns.append({
                'name': name,
                'code': code,
                'date': date,
                'reps': vulns[number]
            })

with open('snyk_vulns.json', 'w') as f:
    json.dump(snyk_vulns, f)