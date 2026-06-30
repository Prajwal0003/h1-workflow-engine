# HackerOne Vulnerability Report

## Title
Unrestricted Google Maps API Key Exposure (Staticmap API Billing Abuse)

## Target
HackerOne (security)
*(Note: You must specify the exact hackerone.com URL where you found this key embedded in the source code!)*

## Weakness
Information Exposure Through Source Code (CWE-311) / API Key Exposure

## Severity
Medium

## Description
Hello HackerOne Security Team,

While analyzing the client-side source code, I found a Google Maps API key embedded in the HTML:
`<script src="https://maps.googleapis.com/maps/api/js?key=AIzaSyDBkjlmLFquI4TIAl4tjyReQPV8vXWl4wk&libraries=places"></script>`

While Google Maps JavaScript API keys are intended to be public, they must be properly secured using HTTP Referrer restrictions in the Google Cloud Console to prevent unauthorized usage on third-party domains. 

Upon testing the key, I discovered that it is **unrestricted** for the **Staticmap API**. An attacker can freely use this API key on their own applications or through automated scripts to generate static maps, resulting in unauthorized billing charges to HackerOne's Google Cloud account.

## Steps to Reproduce
1. Extract the API key `AIzaSyDBkjlmLFquI4TIAl4tjyReQPV8vXWl4wk` from the source code.
2. To verify the lack of restrictions on the Staticmap API, run the following curl command:
   ```bash
   curl -i -s -k -X $'GET' \
       "https://maps.googleapis.com/maps/api/staticmap?center=45%2C10&zoom=7&size=400x400&key=AIzaSyDBkjlmLFquI4TIAl4tjyReQPV8vXWl4wk"
   ```
3. Observe that the API successfully returns the image data (HTTP 200 OK) without enforcing any domain restrictions, proving it can be utilized outside of HackerOne.

## Impact
An attacker can embed this API key into their own website or application to generate map images, maliciously consuming HackerOne's Google Maps quota. Since the Staticmap API charges per request, a simple automated script could run up significant unauthorized charges on your Google Cloud billing account, or lead to a Denial of Service if daily API quotas are exhausted.

## Remediation
1. Go to the Google Cloud Console -> APIs & Services -> Credentials.
2. Select the exposed API key.
3. Under "Application restrictions", select "HTTP referrers (web sites)" and add strict restrictions so it can only be loaded from `*.hackerone.com/*`.
4. Under "API restrictions", ensure the key is only allowed to access the specific Google APIs required by the application.

Best regards,
[Your Name]
