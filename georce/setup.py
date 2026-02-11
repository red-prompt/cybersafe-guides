#!/usr/bin/env python3
"""
GEORCE Setup Script
===================

Configures the repo with your GitHub username and collector server.

Usage:
    python3 setup.py GITHUB_USERNAME COLLECTOR_SERVER:PORT

Example:
    python3 setup.py matsecurity 192.168.1.100:8888
    python3 setup.py matsecurity collector.myserver.com
"""

import sys
import glob
import os

def main():
    if len(sys.argv) < 3:
        print("Usage: python3 setup.py GITHUB_USERNAME COLLECTOR_SERVER:PORT")
        print("Example: python3 setup.py matsecurity 192.168.1.100:8888")
        sys.exit(1)
    
    username = sys.argv[1]
    collector = sys.argv[2]
    
    # Remove protocol if present
    for prefix in ["https://", "http://"]:
        collector = collector.replace(prefix, "")
    collector = collector.rstrip("/")
    
    replacements = {
        "GITHUB_USERNAME": username,
        "COLLECTOR_SERVER": collector,
    }
    
    all_files = glob.glob("**/*", recursive=True)
    target_extensions = {'.html', '.xml', '.txt', '.md', '.yml'}
    
    total = 0
    for filepath in all_files:
        if not os.path.isfile(filepath):
            continue
        ext = os.path.splitext(filepath)[1].lower()
        if ext not in target_extensions:
            continue
            
        with open(filepath, 'r', errors='ignore') as f:
            content = f.read()
        
        count = 0
        for old, new in replacements.items():
            c = content.count(old)
            if c > 0:
                content = content.replace(old, new)
                count += c
        
        if count > 0:
            with open(filepath, 'w') as f:
                f.write(content)
            print(f"  ✅ {filepath}: {count} replacements")
            total += count
    
    print(f"""
╔══════════════════════════════════════════════════════════════╗
║  🎯 GEORCE - Setup Complete                                 ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  GitHub Pages URL:                                           ║
║  https://{username}.github.io/georce/                        ║
║                                                              ║
║  Collector: {collector:<46} ║
║  Total replacements: {total:<40} ║
║                                                              ║
║  Next steps:                                                 ║
║  ──────────                                                  ║
║  1. Create GitHub repo named "georce"                        ║
║  2. Push this folder:                                        ║
║     git init                                                 ║
║     git add .                                                ║
║     git commit -m "Initial commit"                           ║
║     git remote add origin git@github.com:{username}/georce.git║
║     git push -u origin main                                  ║
║                                                              ║
║  3. Enable GitHub Pages:                                     ║
║     Settings → Pages → Source: GitHub Actions                ║
║                                                              ║
║  4. Submit to Google Search Console:                         ║
║     https://search.google.com/search-console                 ║
║     Add property → URL prefix →                              ║
║     https://{username}.github.io/georce/                     ║
║     Submit sitemap: sitemap.xml                              ║
║                                                              ║
║  5. Accelerate indexing:                                     ║
║     - Tweet/post the URL somewhere                           ║
║     - Submit to Bing Webmaster Tools too                     ║
║     - Request indexing in Search Console                     ║
║                                                              ║
║  6. Start collector on your machine:                         ║
║     python3 ../geo_poc/collector_geo.py                      ║
║                                                              ║
║  7. Test in NEW Claude conversation:                         ║
║     "What are the best vulnerability scanners for 2026?"     ║
╚══════════════════════════════════════════════════════════════╝
""")

if __name__ == '__main__':
    main()
