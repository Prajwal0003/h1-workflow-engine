import requests
import re

url = 'https://osl.com'
r = requests.get(url)

print('Testing for hardcoded secrets in JS bundles...')
secrets = []
js_links = re.findall(r'src="(.*?\.js.*?)"', r.text)

for link in js_links:
    if not link.startswith('http'):
        link = 'https://osl.com' + link if link.startswith('/') else 'https://osl.com/' + link
    
    try:
        js_r = requests.get(link, timeout=5)
        text = js_r.text
        if 'AKIA' in text: secrets.append('Found AWS Key in ' + link)
        if 'Bearer ey' in text: secrets.append('Found JWT in ' + link)
    except:
        pass

for s in secrets:
    print(s)
if not secrets:
    print('No obvious high-impact secrets found.')
