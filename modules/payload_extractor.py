import os
import glob
import re

def extract_payloads():
    payloads = {}
    base_dir = "data/Offensive-Pentesting-Web"
    if not os.path.exists(base_dir):
        return payloads
        
    for filepath in glob.glob(f"{base_dir}/**/*.md", recursive=True):
        vuln_type = os.path.basename(os.path.dirname(filepath))
        if vuln_type == "Offensive-Pentesting-Web":
            vuln_type = "General"
            
        if vuln_type not in payloads:
            payloads[vuln_type] = []
            
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                
            # Extract code blocks
            code_blocks = re.findall(r'```(.*?)```', content, re.DOTALL)
            for block in code_blocks:
                lines = [l.strip() for l in block.split('\n') if l.strip() and not l.strip().startswith('http')]
                # Filter out obvious non-payload text like 'html' or 'php'
                lines = [l for l in lines if l not in ['html', 'php', 'bash', 'json', 'xml', 'python']]
                payloads[vuln_type].extend(lines)
                
            # Extract inline code snippets that might be payloads
            inline_codes = re.findall(r'`([^`]+)`', content)
            for code in inline_codes:
                if len(code) > 4 and any(c in code for c in ['<', '>', "'", '"', ';', '/', '\\', '$', '{', '}']):
                    payloads[vuln_type].append(code)
        except Exception:
            pass

    # Clean up and deduplicate
    cleaned_payloads = {}
    for k, v in payloads.items():
        unique_v = list(set(v))
        if unique_v:
            cleaned_payloads[k] = unique_v
            
    return cleaned_payloads
