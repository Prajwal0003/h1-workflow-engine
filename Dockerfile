FROM python:3.11-slim

WORKDIR /app

# Install OS dependencies (git, wget, curl, golang for Go-based tools)
RUN apt-get update && apt-get install -y \
    git wget curl golang nmap \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Node.js for OpenCode MCP
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get update && apt-get install -y nodejs && \
    npm install -g opencode-ai

# Install Python dependencies including playwright, neo4j, and cai-framework
RUN pip install requests urllib3 playwright neo4j flask python-dotenv rich cai-framework

# Install Playwright for headless SPA crawling
RUN playwright install-deps
RUN playwright install chromium

# Copy the rest of the project
COPY . .

# Download ALL tools (Nuclei, FFUF, Subfinder, GAU, httpx, naabu, katana,
# dalfox, dnsx, alterx, notify, interactsh, trufflehog, gitleaks,
# sqlmap, XSStrike, Corsy, Arjun, ParamSpider, CRLFsuite, SSRFmap,
# SSTImap, jwt_tool, wafw00f, LinkFinder, SecretFinder, git-dumper,
# S3Scanner, commix, smuggler, tplmap, XSRFProbe)
RUN python setup_tools.py

# Download industry-standard wordlists (SecLists)
# Already handled by setup_tools.py

# Run as non-root user
RUN useradd -m scanner && chown -R scanner /app
USER scanner

# Command to run the scanner by default (now using the 24/7 daemon)
CMD ["python", "run_24_7.py"]
