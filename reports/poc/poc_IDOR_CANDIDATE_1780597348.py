import requests
import time

start_time = time.time()

# Valid and invalid bookingId's
valid_booking_id = 'admin'
invalid_booking_id = 'invalid-user'

# URLs to test
valid_url = f'https://www.meesho.com/profile?bookingId={valid_booking_id}'
invalid_url = f'https://www.meesho.com/profile?bookingId={invalid_booking_id}'

# Send HTTP requests
start_valid = time.time()
request_valid = requests.head(valid_url)
end_valid = time.time()
print(f"Valid Request Headers: {request_valid.headers}")
print(f"Valid Request Timing: {end_valid - start_valid} seconds")
print(f"Valid Status Code: {request_valid.status_code}")
print(f"Valid Response Message: {request_valid.reason}")

start_invalid = time.time()
request_invalid = requests.head(invalid_url)
end_invalid = time.time()
print(f"Invalid Request Headers: {request_invalid.headers}")
print(f"Invalid Request Timing: {end_invalid - start_invalid} seconds")
print(f"Invalid Status Code: {request_invalid.status_code}")
print(f"Invalid Response Message: {request_invalid.reason}")

# Check if response content differs between valid and invalid ID
if request_valid.text != request_invalid.text:
    print(f"Response differs between valid and invalid ID: {request_valid.text != request_invalid.text}")
else:
    print(f"No difference in response content.")

# Determine if vulnerability is verified
if f'bookingId={valid_booking_id}' in request_valid.text or 'admin' in request_valid.text:
    verdict = 'VERIFIED: VULNERABLE'
else:
    verdict = 'NOT VERIFIED'

print(verdict)
```

Note: As per the constraints, I am using `requests.head()` method to send a HEAD request, which retrieves the response headers and status line (i.e., HTTP version, status code, reason phrase) without the response body.