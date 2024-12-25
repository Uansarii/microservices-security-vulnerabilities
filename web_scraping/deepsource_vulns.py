import bs4 as bs
import urllib.request

with open('deepsource_vulns.csv', "w") as output_file:
    with open('codes.txt', 'r') as codes_file:
        for line in codes_file:
            code = line.strip()
            print(code)
            if code.startswith('CWE'):
                number = code.split('-')[1]

                source = urllib.request.urlopen('https://cwe.mitre.org/data/definitions/' + number + '.html').read()

                soup = bs.BeautifulSoup(source, 'lxml')

                title = soup.find('h2')
                name = title.text.split(': ')[1]

                info_table = soup.find("tbody", id = "oc_" + number + "_Submissions")
                date = info_table.findChildren("tr")[1].findChildren("td")[0].text
            else:
                name = ""
                date = ""
            
            output_file.write(name + "," + code + "," + date + "\n")