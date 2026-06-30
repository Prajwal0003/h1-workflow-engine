import urllib.request, re, json, urllib.parse
query = urllib.parse.quote('"never on youtube kids"')
h = urllib.request.urlopen(f'https://www.youtube.com/results?search_query={query}').read().decode('utf-8')
m = re.search(r'ytInitialData = ({.*?});</script>', h)
if m:
    d = json.loads(m.group(1))
    c = d.get('contents', {}).get('twoColumnSearchResultsRenderer', {}).get('primaryContents', {}).get('sectionListRenderer', {}).get('contents', [])
    for i in c:
        for j in i.get('itemSectionRenderer', {}).get('contents', []):
            v = j.get('videoRenderer')
            if v: print(v.get('title', {}).get('runs', [{}])[0].get('text', ''), '|', v.get('lengthText', {}).get('simpleText', ''), '|', v.get('ownerText', {}).get('runs', [{}])[0].get('text', ''), '|', v.get('videoId', ''))
