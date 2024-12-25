import bs4 as bs
import urllib.request

source = urllib.request.urlopen('https://avd.aquasec.com/misconfig/ksv024').read()
soup = bs.BeautifulSoup(source, 'lxml')

source2 = urllib.request.urlopen(soup.title.text).read()
soup2 = bs.BeautifulSoup(source2, 'lxml')

severity_divs = soup2.find_all(class_ = "avdcve_scores_cvss")
score = severity_divs[0]['class'][1].split("_")[1]
print(score)

info_div = soup2.find_all("div", class_="vulnerability_content")[0]
print(info_div.findChildren("h3")[0].text)