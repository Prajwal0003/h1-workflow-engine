import argparse
import requests
import json
import urllib3
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# We'll use common bucket name permutations
PERMUTATIONS = [
    "{target}", "{target}-dev", "{target}-prod", "{target}-staging",
    "{target}-qa", "{target}-assets", "{target}-public", "{target}-media",
    "{target}-backup", "{target}-logs", "dev-{target}", "prod-{target}"
]

PROVIDERS = {
    "AWS S3": "https://{bucket}.s3.amazonaws.com",
    "GCP Storage": "https://storage.googleapis.com/{bucket}",
    "Azure Blob": "https://{bucket}.blob.core.windows.net"
}

def check_bucket(provider_name, url_template, bucket_name):
    url = url_template.format(bucket=bucket_name)
    try:
        r = requests.get(url, timeout=5, verify=False)
        # 200 OK with ListBucketResult implies exposed bucket listing!
        if r.status_code == 200 and ("ListBucketResult" in r.text or "Blob" in r.text):
            return {"provider": provider_name, "bucket": bucket_name, "url": url, "status": "OPEN_LISTING"}
        # 403 Forbidden means it exists but is private
        elif r.status_code == 403 and ("AccessDenied" in r.text or "AuthenticationFailed" in r.text):
            return {"provider": provider_name, "bucket": bucket_name, "url": url, "status": "PRIVATE_EXISTS"}
    except Exception:
        pass
    return None

def main():
    parser = argparse.ArgumentParser(description="Cloud Bucket Sniper - Find exposed AWS/GCP/Azure buckets.")
    parser.add_argument("target", help="Target handle (e.g., nba-public)")
    args = parser.parse_args()
    
    target_clean = args.target.replace("-public", "").replace("-", "")
    print(f"[*] Starting Cloud Sniper for target: {args.target} (base string: {target_clean})")
    
    tasks = []
    results = []
    
    with ThreadPoolExecutor(max_workers=20) as executor:
        for perm in PERMUTATIONS:
            bucket_name = perm.format(target=target_clean)
            for p_name, p_url in PROVIDERS.items():
                tasks.append(executor.submit(check_bucket, p_name, p_url, bucket_name))
                
        for future in tasks:
            res = future.result()
            if res:
                results.append(res)
                if res["status"] == "OPEN_LISTING":
                    print(f"[!] CRITICAL: Open {res['provider']} bucket found: {res['url']}")
                else:
                    print(f"[+] Found private {res['provider']} bucket: {res['url']}")
                    
    if not results:
        print("[-] No cloud buckets found for this target.")
        
    out_file = Path("data/recon") / f"{args.target}_buckets.json"
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(json.dumps(results, indent=2))
    print(f"[*] Cloud Sniper finished. Saved to {out_file}")

if __name__ == "__main__":
    main()
