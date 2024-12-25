import bs4 as bs
import urllib.request

code = 'CWE-352'
number = code.split('-')[1]

source = urllib.request.urlopen('https://cwe.mitre.org/data/definitions/' + number + '.html').read()

soup = bs.BeautifulSoup(source, 'lxml')

title = soup.find('h2')
name = title.text.split(': ')[1]
print(name)

info_table = soup.find("tbody", id = "oc_" + number + "_Submissions")
date = info_table.findChildren("tr")[1].findChildren("td")[0].text
print(date)