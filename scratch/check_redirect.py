import urllib.request
import ssl
import urllib.error

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def http_error_302(self, req, fp, code, msg, headers):
        return urllib.response.addinfourl(fp, headers, req.get_full_url(), code)
    http_error_301 = http_error_303 = http_error_307 = http_error_302

opener = urllib.request.build_opener(NoRedirectHandler, urllib.request.HTTPSHandler(context=ctx))
req = urllib.request.Request('https://api.adm.cloud.com?url=//evil.com', headers={'User-Agent': 'Mozilla/5.0'})
try:
    res = opener.open(req)
    print("Status:", res.code)
    print("Location:", res.headers.get('Location'))
except urllib.error.HTTPError as e:
    print("Error:", e.code)
    print("Location:", e.headers.get('Location'))
