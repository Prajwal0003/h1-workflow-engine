import requests
from rich.console import Console
from urllib.parse import urlparse

console = Console()

def check_cswsh(url, headers=None):
    """
    Cross-Site WebSocket Hijacking (CSWSH) Scanner.
    Many modern applications use WebSockets for real-time data but fail to validate the Origin header.
    This module attempts to initiate a WebSocket handshake with an attacker-controlled Origin.
    """
    console.print(f"[bold cyan][*] Scanning for Cross-Site WebSocket Hijacking (CSWSH): {url}[/bold cyan]")
    
    findings = []
    parsed = urlparse(url)
    
    # WebSocket endpoints usually have 'ws' or 'socket' in the path, or are wss://
    # Here we just try to upgrade the connection on the given URL
    
    ws_headers = headers.copy() if headers else {}
    ws_headers.update({
        "Connection": "Upgrade",
        "Upgrade": "websocket",
        "Sec-WebSocket-Version": "13",
        "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
        "Origin": "https://evil-attacker.com" # The malicious Origin
    })
    
    try:
        # We use a standard GET request but with WebSocket upgrade headers
        response = requests.get(url, headers=ws_headers, timeout=5)
        
        # If the server responds with 101 Switching Protocols AND doesn't reject our evil Origin
        if response.status_code == 101 and response.headers.get("Upgrade", "").lower() == "websocket":
            console.print(f"[bold red][!] CRITICAL: Cross-Site WebSocket Hijacking (CSWSH) detected![/bold red]")
            console.print(f"[bold red]    Server accepted WebSocket connection from Origin: https://evil-attacker.com[/bold red]")
            findings.append(f"CSWSH: {url} accepted cross-origin WebSocket handshake.")
    except requests.exceptions.RequestException:
        pass
        
    if not findings:
        console.print("[green][+] No Cross-Site WebSocket Hijacking vulnerabilities detected.[/green]")
        
    return findings
