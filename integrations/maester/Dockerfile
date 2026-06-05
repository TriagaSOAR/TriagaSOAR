FROM mcr.microsoft.com/powershell:7.4-ubuntu-22.04

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

# Install required PowerShell modules
RUN pwsh -NoProfile -Command "\
    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted; \
    Install-Module -Name Maester -Force -Scope AllUsers; \
    Install-Module -Name Microsoft.Graph.Authentication -Force -Scope AllUsers; \
    Install-Module -Name Microsoft.Graph.Identity.SignIns -Force -Scope AllUsers; \
    Install-Module -Name Microsoft.Graph.Reports -Force -Scope AllUsers"

WORKDIR /app
COPY run_maester.ps1 .

ENV MAESTER_TENANT_ID=""
ENV MAESTER_CLIENT_ID=""
ENV MAESTER_CLIENT_SECRET=""
ENV MAESTER_INTERVAL_MINUTES="60"
ENV MAESTER_OUTPUT_DIR="/app/output"

RUN mkdir -p /app/output

CMD ["pwsh", "-NoProfile", "-File", "/app/run_maester.ps1"]