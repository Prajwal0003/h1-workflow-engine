import requests
import concurrent.futures
import sys
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

url = sys.argv[1].rstrip("/")
print(f"[*] Rapid API Bruteforcer starting against {url}")

common_paths = [
    '/api', '/api/v1', '/api/v2', '/v1', '/v2', '/graphql', '/admin', '/api/admin',
    '/swagger-ui.html', '/api-docs', '/v3/api-docs', '/actuator', '/actuator/env',
    '/server-status', '/.env', '/config', '/api/users', '/api/v1/users', '/debug',
    '/test', '/staging', '/api/staging', '/stg', '/dev', '/api/dev', '/health',
    '/ping', '/status', '/metrics', '/api/metrics', '/_cat/indices', '/_cluster/health'
]

# Generate more permutations
versions = ['v1', 'v2', 'v3', 'v4']
objects = ['users', 'admin', 'auth', 'login', 'dashboard', 'settings', 'config', 'data', 'orders', 'products', 'upload', 'files']

for v in versions:
    for o in objects:
        common_paths.append(f'/api/{v}/{o}')
        common_paths.append(f'/{v}/{o}')
        common_paths.append(f'/api/{o}')
        common_paths.append(f'/{o}')

common_paths = list(set(common_paths))

def check_path(path):
    target = url + path
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'X-Forwarded-For': '127.0.0.1',
        'X-Original-URL': '/admin',
        'Accept': 'application/json, text/plain, */*'
    }
    try:
        r = requests.get(target, headers=headers, timeout=5, verify=False)
        if r.status_code not in [404, 403, 400]:
            snippet = r.text[:80].replace('\n', ' ').strip()
            if 'html' in r.headers.get('Content-Type', ''):
                return f"[+] {r.status_code} | {path.ljust(30)} | HTML Page"
            elif snippet:
                return f"[+] {r.status_code} | {path.ljust(30)} | {snippet}"
            else:
                return f"[+] {r.status_code} | {path.ljust(30)} | Empty Response"
    except Exception:
        pass
    return None

results = []
with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
    futures = {executor.submit(check_path, path): path for path in common_paths}
    for future in concurrent.futures.as_completed(futures):
        res = future.result()
        if res:
            results.append(res)
            print(res)

print(f"\n[*] Bruteforce complete. Found {len(results)} active endpoints.")
