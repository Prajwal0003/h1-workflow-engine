import sys
import json
import asyncio
from pathlib import Path
from playwright.async_api import async_playwright

async def take_screenshot(context, url, out_path):
    page = await context.new_page()
    try:
        # 10s timeout, wait until network is mostly idle
        await page.goto(url, timeout=10000, wait_until="networkidle")
        await page.screenshot(path=str(out_path), full_page=False)
        print(f"[+] Screenshot saved: {url}")
        return str(out_path.name)
    except Exception as e:
        print(f"[-] Failed to screenshot {url}: {str(e).splitlines()[0][:60]}")
        return None
    finally:
        await page.close()

async def main():
    target_file = sys.argv[1] if len(sys.argv) > 1 else None
    if not target_file or not Path(target_file).exists():
        print("Usage: python visual_recon.py <path_to_live_urls.json>")
        print("Example: python visual_recon.py data/vimeo_known_live.json")
        return

    try:
        urls = json.loads(Path(target_file).read_text())
        if not isinstance(urls, list):
            raise ValueError
    except Exception:
        print("[-] Error: Input file must contain a JSON array of URLs.")
        return

    screenshots_dir = Path("reports/screenshots")
    screenshots_dir.mkdir(parents=True, exist_ok=True)
    
    html_content = """
    <html>
    <head>
        <title>Visual Recon Report</title>
        <style>
            body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #121212; color: #ffffff; margin: 30px; }
            h1 { border-bottom: 2px solid #333; padding-bottom: 10px; }
            .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(450px, 1fr)); gap: 25px; margin-top: 20px;}
            .card { background: #1e1e1e; border-radius: 10px; padding: 15px; text-align: center; box-shadow: 0 4px 6px rgba(0,0,0,0.3); transition: transform 0.2s;}
            .card:hover { transform: translateY(-5px); border: 1px solid #4da6ff;}
            .card img { max-width: 100%; height: auto; border-radius: 6px; border: 1px solid #333; margin-top: 10px;}
            .card a { color: #4da6ff; text-decoration: none; word-wrap: break-word; font-weight: bold; font-size: 1.1em;}
            .card a:hover { text-decoration: underline; }
        </style>
    </head>
    <body>
        <h1>👁️ Aegis-Auto Visual Reconnaissance</h1>
        <p>Click on any image or link to open the target directly.</p>
        <div class="grid">
    """

    print(f"[*] Starting Visual Recon for {len(urls)} URLs...")
    
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        # ignore https errors for self-signed certs
        context = await browser.new_context(ignore_https_errors=True, viewport={'width': 1280, 'height': 800})
        
        # Process in batches to avoid overwhelming the system
        batch_size = 5
        results_map = []
        
        for i in range(0, len(urls), batch_size):
            batch = urls[i:i+batch_size]
            tasks = []
            for j, url in enumerate(batch):
                idx = i + j
                out_name = screenshots_dir / f"screen_{idx}.png"
                tasks.append(take_screenshot(context, url, out_name))
            
            batch_results = await asyncio.gather(*tasks)
            results_map.extend(zip(batch, batch_results))
        
        for url, img_name in results_map:
            if img_name:
                html_content += f'''
                <div class="card">
                    <a href="{url}" target="_blank">{url}</a>
                    <a href="{url}" target="_blank">
                        <img src="screenshots/{img_name}" loading="lazy" alt="Screenshot of {url}">
                    </a>
                </div>
                '''
                
        await browser.close()
        
    html_content += "</div></body></html>"
    report_path = Path("reports/visual_recon.html")
    report_path.write_text(html_content, encoding="utf-8")
    print(f"\n[***] Visual Recon Complete! [***]")
    print(f"[***] Open this file in your browser: file://{report_path.absolute()} [***]")

if __name__ == "__main__":
    asyncio.run(main())
