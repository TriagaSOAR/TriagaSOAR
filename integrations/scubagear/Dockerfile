FROM mcr.microsoft.com/powershell:7.4-ubuntu-22.04

RUN apt-get update && apt-get install -y ca-certificates curl unzip python3 && rm -rf /var/lib/apt/lists/*

# Download ScubaGear source
RUN pwsh -NoProfile -Command "\
    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted; \
    Save-Module -Name ScubaGear -Path /tmp/scubagear-src -Force; \
    \$ver = (Get-ChildItem /tmp/scubagear-src/ScubaGear -Directory | Sort-Object Name -Descending | Select-Object -First 1).Name; \
    Write-Host \"Saved ScubaGear \$ver\""

# Copy patch script and run it
COPY patch_windows_principal.py /tmp/patch_windows_principal.py
RUN python3 /tmp/patch_windows_principal.py /tmp/scubagear-src

# Run patch again to catch any nested patterns missed on first pass
RUN python3 /tmp/patch_windows_principal.py /tmp/scubagear-src

# Install patched module
RUN pwsh -NoProfile -Command "\
    \$src = Get-ChildItem /tmp/scubagear-src/ScubaGear -Directory | Sort-Object Name -Descending | Select-Object -First 1; \
    \$dest = '/usr/local/share/powershell/Modules/ScubaGear'; \
    if (Test-Path \$dest) { Remove-Item -Recurse -Force \$dest }; \
    Copy-Item -Recurse -Force \$src.FullName \$dest; \
    Write-Host \"Installed ScubaGear from \$(\$src.Name)\""

# Install ScubaGear required dependencies at exact versions
RUN pwsh -NoProfile -Command "\
    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted; \
    Install-Module -Name MicrosoftTeams -RequiredVersion 7.7.0 -Force -Scope AllUsers -AllowClobber; \
    Install-Module -Name ExchangeOnlineManagement -RequiredVersion 3.7.1 -Force -Scope AllUsers; \
    Install-Module -Name Microsoft.Graph.Authentication -RequiredVersion 2.25.0 -Force -Scope AllUsers; \
    Install-Module -Name powershell-yaml -Force -Scope AllUsers; \
    Write-Host 'Dependencies installed'"

# Install OPA binary for Linux at the path ScubaGear expects
RUN pwsh -NoProfile -Command "\
    \$version = '0.68.0'; \
    \$opaDir = '/root/.scubagear/Tools'; \
    New-Item -ItemType Directory -Path \$opaDir -Force | Out-Null; \
    \$url = \"https://github.com/open-policy-agent/opa/releases/download/v\$version/opa_linux_amd64_static\"; \
    Invoke-WebRequest -Uri \$url -OutFile \"\$opaDir/opa_linux_amd64_static\" -UseBasicParsing; \
    chmod +x \"\$opaDir/opa_linux_amd64_static\"; \
    New-Item -ItemType SymbolicLink -Path \"\$opaDir/opa\" -Target \"\$opaDir/opa_linux_amd64_static\" -Force | Out-Null; \
    ls -la \$opaDir; \
    Write-Host 'OPA installed'"

# Verify module loads
RUN pwsh -NoProfile -Command "\
    \$env:SCUBAGEAR_SKIP_VERSION_CHECK = 'true'; \
    Import-Module ScubaGear -ErrorAction Stop; \
    Write-Host 'ScubaGear loaded OK'"

WORKDIR /app
COPY run_scubagear.ps1 .

ENV SCUBAGEAR_TENANT_ID=""
ENV SCUBAGEAR_CLIENT_ID=""
ENV SCUBAGEAR_CERT_THUMBPRINT=""
ENV SCUBAGEAR_ORGANIZATION=""
ENV SCUBAGEAR_INTERVAL_MINUTES="60"
ENV SCUBAGEAR_OUTPUT_DIR="/app/output"
ENV SCUBAGEAR_SKIP_VERSION_CHECK="true"
ENV USERPROFILE="/root"

RUN mkdir -p /app/output /app/certs

CMD ["pwsh", "-NoProfile", "-File", "/app/run_scubagear.ps1"]