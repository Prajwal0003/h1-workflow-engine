# HackerOne Vulnerability Report

## Title
CRITICAL: Unrestricted Google Maps API Key Exposure in Public S3 Bucket JS Bundle

## Target
Vimeo (https://s3-us-west-2.amazonaws.com/zuora-project-kong/temp/dist/main.bundle.js)

## Weakness
Information Exposure Through Source Code (CWE-311) / API Key Exposure

## Severity
High / Critical (depending on program guidelines for billing abuse)

## Description
Hello Vimeo Security Team,

During my reconnaissance, I discovered a public JavaScript bundle hosted on an AWS S3 bucket belonging to Vimeo (project `zuora-project-kong`). The bundle (`main.bundle.js`) contains a hardcoded Google Maps API Key (`AIzaSyDe8cSSAnIS6ns7wc89l4Kph2kRJvWJ26A`). 

Upon further investigation, I discovered that this API key is completely unrestricted. It lacks HTTP referrer restrictions, IP address restrictions, or application restrictions. This means that a malicious actor can take this API key and use it in their own applications or scripts to make an unlimited amount of API calls at Vimeo's expense. 

I validated this by testing the key against several Google Maps API endpoints. The key successfully allowed queries to the **Geocoding API** and **Find Place API**, both of which are paid services.

## Steps to Reproduce
1. Navigate to the exposed JavaScript bundle:
   `https://s3-us-west-2.amazonaws.com/zuora-project-kong/temp/dist/main.bundle.js`
2. Search the response text for the string `AIzaSy`. You will find the API key `AIzaSyDe8cSSAnIS6ns7wc89l4Kph2kRJvWJ26A`.
3. To verify that the key is unrestricted and vulnerable to billing abuse, execute a `curl` request to the Geocoding API:
   ```bash
   curl -s "https://maps.googleapis.com/maps/api/geocode/json?address=New+York&key=AIzaSyDe8cSSAnIS6ns7wc89l4Kph2kRJvWJ26A"
   ```
4. Observe that the API returns a successful `200 OK` response with the geocoding data for New York, instead of a `REQUEST_DENIED` error.
5. Similarly, test the Find Place API:
   ```bash
   curl -s "https://maps.googleapis.com/maps/api/place/findplacefromtext/json?input=Museum&inputtype=textquery&key=AIzaSyDe8cSSAnIS6ns7wc89l4Kph2kRJvWJ26A"
   ```
6. Observe the successful `200 OK` response with place data.

## Impact
Since the API key is unrestricted, anyone can utilize this key on their own websites, applications, or through automated scripts. This can lead to severe financial damage (billing abuse) and quota exhaustion (denial of service for the legitimate application relying on this key). Google charges for these APIs per request, meaning an attacker could easily script thousands of requests to rack up significant charges on Vimeo's Google Cloud billing account.

## Remediation
1. **Revoke and Regenerate**: Immediately revoke the exposed API key in the Google Cloud Console and generate a new one.
2. **Apply Restrictions**: Ensure the newly generated API key has strict HTTP referrer restrictions applied so it can only be used by authorized domains (e.g., `*.vimeo.com/*`). Additionally, restrict the API key to only the specific Google APIs that your application requires.
3. **Remove Hardcoded Secrets**: Ensure that the S3 bucket is either made private if it should not be public, or remove the hardcoded secrets from the JS bundles prior to deployment.

Let me know if you need any more information.

Best regards,
[Your Name / HackerOne Handle]
