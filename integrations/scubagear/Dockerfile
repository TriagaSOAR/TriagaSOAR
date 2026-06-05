FROM mcr.microsoft.com/powershell:7.4-ubuntu-22.04

RUN apt-get update && apt-get install -y ca-certificates curl unzip && rm -rf /var/lib/apt/lists/*

# Download ScubaGear source and patch out Windows Principal check
RUN pwsh -NoProfile -Command "\
    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted; \
    Save-Module -Name ScubaGear -Path /tmp/scubagear-src -Force"

# Patch out the WindowsIdentity::GetCurrent() call that fails on Linux
RUN find /tmp/scubagear-src -name "*.psm1" -o -name "*.ps1" | \
    xargs grep -l "WindowsIdentity" | \
    while read f; do \
        sed -i 's/\[System\.Security\.Principal\.WindowsIdentity\]::GetCurrent()/"Linux-Container"/g' "$f"; \
        sed -i 's/\[Security\.Principal\.WindowsIdentity\]::GetCurrent()/"Linux-Container"/g' "$f"; \
    done

# Install patched module
RUN pwsh -NoProfile -Command "\
    \$src = Get-ChildItem /tmp/scubagear-src/ScubaGear -Directory | Sort-Object Name -Descending | Select-Object -First 1; \
    Copy-Item -Recurse -Force \$src.FullName '/usr/local/share/powershell/Modules/ScubaGear'; \
    Write-Host 'ScubaGear installed from patched source'"

# Install OPA binary for Linux
RUN pwsh -NoProfile -Command "\
    Import-Module ScubaGear -ErrorAction SilentlyContinue; \
    \$version = '0.68.0'; \
    \$opaDir = '/root/.scubagear/Tools'; \
    New-Item -ItemType Directory -Path \$opaDir -Force | Out-Null; \
    \$url = \"https://github.com/open-policy-agent/opa/releases/download/v\$version/opa_linux_amd64_static\"; \
    Invoke-WebRequest -Uri \$url -OutFile \"\$opaDir/opa_linux_amd64\" -UseBasicParsing; \
    chmod +x \"\$opaDir/opa_linux_amd64\"; \
    Write-Host 'OPA installed'"

WORKDIR /app
COPY run_scubagear.ps1 .

ENV SCUBAGEAR_TENANT_ID=""
ENV SCUBAGEAR_CLIENT_ID=""
ENV SCUBAGEAR_CERT_THUMBPRINT=""
ENV SCUBAGEAR_ORGANIZATION=""
ENV SCUBAGEAR_INTERVAL_MINUTES="60"
ENV SCUBAGEAR_OUTPUT_DIR="/app/output"
ENV SCUBAGEAR_SKIP_VERSION_CHECK="true"

RUN mkdir -p /app/output /app/certs

CMD ["pwsh", "-NoProfile", "-File", "/app/run_scubagear.ps1"]