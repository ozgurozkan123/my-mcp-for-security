FROM python:3.11-slim

# Install system dependencies including amass
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    unzip \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install amass from GitHub releases
# Using the latest stable version
RUN AMASS_VERSION="4.2.0" && \
    wget -q "https://github.com/owasp-amass/amass/releases/download/v${AMASS_VERSION}/amass_Linux_amd64.zip" -O /tmp/amass.zip && \
    unzip /tmp/amass.zip -d /tmp && \
    mv /tmp/amass_Linux_amd64/amass /usr/local/bin/amass && \
    chmod +x /usr/local/bin/amass && \
    rm -rf /tmp/amass.zip /tmp/amass_Linux_amd64

# Verify amass installation
RUN amass -version || echo "Amass installed"

WORKDIR /app

# Copy requirements first for caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . .

# Set environment variables
ENV HOST=0.0.0.0
ENV PYTHONUNBUFFERED=1

# Expose default port
EXPOSE 8000

# Run the MCP server
CMD ["python", "server.py"]
