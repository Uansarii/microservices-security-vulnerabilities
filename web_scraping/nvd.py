import bs4 as bs
import urllib.request

source = urllib.request.urlopen('https://nvd.nist.gov/vuln/detail/CVE-2016-1000027').read()

soup = bs.BeautifulSoup(source, 'lxml')

'''
div = soup.find_all("div", class_="bs-callout-info")[0]
children = div.findChildren("strong", recursive=False)
for child in children:
    break
    print(child)
'''


names = soup.find_all("td", attrs={'data-testid': "vuln-CWEs-link-0"})

if len(names) > 0:
    name = names[1]
    print(name.text.strip())


date = soup.find_all("span", attrs={'data-testid': "vuln-published-on"})[0]
print(date.text)

severities = soup.find_all("a", id="Cvss3CnaCalculatorAnchor") + soup.find_all("a", id="Cvss3NistCalculatorAnchor")
severity = severities[0]
score = severity.text.split(" ")[0]
print(score)