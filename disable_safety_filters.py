import os
import glob
import re

files_to_patch = [
    "autopilot.py",
    "modules/ai_triage.py",
    "modules/context_payloads.py",
    "modules/waf_evasion.py"
]

safety_settings = """
    payload["safetySettings"] = [
        {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
        {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
        {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
        {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"}
    ]
"""

for f in files_to_patch:
    if not os.path.exists(f):
        continue
    content = open(f, "r", encoding="utf-8").read()
    
    # Check if already patched
    if "HARM_CATEGORY_DANGEROUS_CONTENT" in content:
        print(f"Skipping {f}, already patched.")
        continue
    
    # Find all occurrences of `payload = {` or `payload = {"contents":`
    # We will inject the safetySettings right before requests.post
    
    # A simple regex to find `requests.post(url, json=payload` and inject the code before it
    new_content = re.sub(
        r'(\s+)([^#\n]*?requests\.post\([^)]*json=payload[^)]*\))',
        lambda m: m.group(1) + safety_settings.replace('\n', '\n' + m.group(1)[1:]) + m.group(1) + m.group(2),
        content
    )
    
    if new_content != content:
        open(f, "w", encoding="utf-8").write(new_content)
        print(f"Patched {f}!")
    else:
        print(f"Could not patch {f}.")
