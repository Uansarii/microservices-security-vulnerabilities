import bs4 as bs
import urllib.request

x = 0

with open("vulns.csv", "w") as output_file:
    with open("frequency.csv", "r") as codes_file:
        for line in codes_file:
            if x == 0:
                x += 1
                continue
            line = line.strip()
            parts = line.split(",")
            code = parts[0]
            reps = parts[1]
            print(code)
            if 'CVE' in code:
                source = urllib.request.urlopen('https://nvd.nist.gov/vuln/detail/' + code).read()
                soup = bs.BeautifulSoup(source, 'lxml')
                names = soup.find_all("td", attrs={'data-testid': "vuln-CWEs-link-0"})

                if len(names) > 0:
                    name = names[1]
                    name = name.text.strip()
                else:
                    name = ""

                dates = soup.find_all("span", attrs={'data-testid': "vuln-published-on"})
                if len(dates) > 0:
                    date = dates[0]
                    date = date.text
                else:
                    date = ""

                severities = soup.find_all("a", id="Cvss3CnaCalculatorAnchor") + soup.find_all("a", id="Cvss3NistCalculatorAnchor")
                if len(severities) > 0:
                    severity = severities[0]
                    score = severity.text.split(" ")[0]
                else:
                    score = ""
            else:
                source = urllib.request.urlopen('https://avd.aquasec.com/misconfig/' + code).read()
                soup = bs.BeautifulSoup(source, 'lxml')

                source2 = urllib.request.urlopen(soup.title.text).read()
                soup2 = bs.BeautifulSoup(source2, 'lxml')

                severity_divs = soup2.find_all(class_ = "avdcve_scores_cvss")
                score = severity_divs[0]['class'][1].split("_")[1]

                info_div = soup2.find_all("div", class_="vulnerability_content")[0]
                name = info_div.findChildren("h3")[0].text

                date = ""

            output_file.write(name + "," + code + "," + date + "," + score + "," + reps + "\n")

            

