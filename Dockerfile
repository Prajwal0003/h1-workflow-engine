FROM python:3.11-slim

WORKDIR /app

# Install OS dependencies
RUN apt-get update && apt-get install -y git wget curl golang && rm -rf /var/lib/apt/lists/*

# Install python dependencies including playwright and neo4j
RUN pip install requests urllib3 playwright neo4j flask
RUN playwright install-deps
RUN playwright install chromium

# Copy the rest of the project
COPY . .

# Download tools and wordlists (Linux binaries will be fetched automatically)
RUN python setup_tools.py

# Command to run the scanner by default
CMD ["python", "autopilot.py"]
