import urllib.request
import re
import json

def search(query):
    html = urllib.request.urlopen(f'https://www.youtube.com/results?search_query={urllib.parse.quote(query)}').read().decode('utf-8')
    data_match = re.search(r'ytInitialData = ({.*?});</script>', html)
    if not data_match: return
    data = json.loads(data_match.group(1))
    
    contents = data.get('contents', {}).get('twoColumnSearchResultsRenderer', {}).get('primaryContents', {}).get('sectionListRenderer', {}).get('contents', [])
    for item in contents:
        for item2 in item.get('itemSectionRenderer', {}).get('contents', []):
            video = item2.get('videoRenderer')
            if video:
                title = video.get('title', {}).get('runs', [{}])[0].get('text', '')
                length = video.get('lengthText', {}).get('simpleText', '')
                owner = video.get('ownerText', {}).get('runs', [{}])[0].get('text', '')
                vid = video.get('videoId', '')
                print(f"{title} | {owner} | {length} | {vid}")

search('Liminal Memories')
search('Liminal Memories youtube kids')
