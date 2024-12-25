import bs4 as bs
import urllib.request

code = 'JAVA-S1060'
lang = code.split('-')[0].lower()

url = 'https://deepsource.io/directory/analyzers/'

if lang == 'java':
    url += 'java/'
elif lang == 'js':
    url += 'javascript/'
elif lang == 'BAN':
    url += 'demo-python/'
elif lang == 'cs':
    url += 'csharp/'
elif lang == 'SCT':
    url += 'secrets/'

url += 'issues/' + code

source = urllib.request.urlopen(url).read()

soup = bs.BeautifulSoup(source, 'lxml')
print(soup.title.text)