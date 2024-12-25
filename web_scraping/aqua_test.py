import bs4 as bs
import urllib.request

source = urllib.request.urlopen('https://avd.aquasec.com/misconfig/dockerfile/general/avd-ds-0002').read()

soup = bs.BeautifulSoup(source, 'lxml')

severity_divs = soup.find_all(class_ = "avdcve_scores_cvss")
score = severity_divs[0]['class'][1].split("_")[1]
print(score)

info_div = soup.find_all("div", class_="vulnerability_content")[0]
print(info_div.findChildren("h3")[0].text)

