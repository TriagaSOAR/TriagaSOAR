$tenantId    = $env:SCUBAGEAR_TENANT_ID
$clientId    = $env:SCUBAGEAR_CLIENT_ID
$thumbprint  = $env:SCUBAGEAR_CERT_THUMBPRINT
$org         = $env:SCUBAGEAR_ORGANIZATION
$intervalMin = [int]($env:SCUBAGEAR_INTERVAL_MINUTES ?? "60")
$outputDir   = $env:SCUBAGEAR_OUTPUT_DIR ?? "/app/output"
$certsDir    = "/app/certs"

if (-not $tenantId -or -not $clientId -or -not $thumbprint -or -not $org) {
    Write-Error "[scubagear] SCUBAGEAR_TENANT_ID, SCUBAGEAR_CLIENT_ID, SCUBAGEAR_CERT_THUMBPRINT, SCUBAGEAR_ORGANIZATION must be set"
    exit 1
}

function Import-PfxToCertStore {
    $pfxPath = Join-Path $certsDir "scubagear.pfx"
    if (-not (Test-Path $pfxPath)) {
        Write-Error "[scubagear] Certificate not found at $pfxPath"
        exit 1
    }
    Write-Host "[scubagear] Importing certificate from $pfxPath"
    $flags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::MachineKeySet -bor
             [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
        $pfxPath, "", $flags
    )
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store(
        [System.Security.Cryptography.X509Certificates.StoreName]::My,
        [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser
    )
    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
    $store.Add($cert)
    $store.Close()
    Write-Host "[scubagear] Certificate imported, thumbprint: $($cert.Thumbprint)"
}

function Invoke-ScubaRun {
    Write-Host "[scubagear] Starting run at $(Get-Date -Format 'o')"

    try {
        Import-PfxToCertStore

        $timestamp  = Get-Date -Format "yyyyMMdd-HHmmss"
        $reportPath = Join-Path $outputDir "scubagear-$timestamp"
        New-Item -ItemType Directory -Path $reportPath -Force | Out-Null

        Write-Host "[scubagear] Running Invoke-SCuBA..."

        # Set USERPROFILE so ScubaGear resolves ~/.scubagear/Tools for OPA
        $env:USERPROFILE = "/root"
        $opaPath = "/root/.scubagear/Tools"

        # Only aad — Teams/EXO cert auth broken on Linux X509Store
        Invoke-SCuBA `
            -ProductNames aad `
            -CertificateThumbprint $thumbprint `
            -AppID $clientId `
            -Organization $org `
            -OutPath $reportPath `
            -OPAPath $opaPath `
            -Quiet `
            -DisconnectOnExit

        # ScubaGear outputs a JSON results file — find it
        $jsonFile = Get-ChildItem -Path $reportPath -Filter "*ScubaResults*.json" -Recurse |
                    Sort-Object LastWriteTime -Descending |
                    Select-Object -First 1

        if (-not $jsonFile) {
            # Fallback: any json
            $jsonFile = Get-ChildItem -Path $reportPath -Filter "*.json" -Recurse |
                        Where-Object { $_.Name -notlike "*ProviderSettings*" } |
                        Sort-Object LastWriteTime -Descending |
                        Select-Object -First 1
        }

        if ($jsonFile) {
            $latestPath = Join-Path $outputDir "latest.json"
            Copy-Item -Path $jsonFile.FullName -Destination $latestPath -Force
            Write-Host "[scubagear] Report written to $latestPath"

            $meta = @{
                last_run    = (Get-Date -Format "o")
                report_file = $jsonFile.Name
                report_path = $reportPath
                status      = "success"
            } | ConvertTo-Json
            $meta | Set-Content (Join-Path $outputDir "status.json") -Force
        } else {
            Write-Warning "[scubagear] No JSON output found in $reportPath"
            $meta = @{
                last_run = (Get-Date -Format "o")
                status   = "no_output"
            } | ConvertTo-Json
            $meta | Set-Content (Join-Path $outputDir "status.json") -Force
        }

    } catch {
        Write-Error "[scubagear] Run failed: $_"
        $meta = @{
            last_run = (Get-Date -Format "o")
            status   = "error"
            error    = $_.ToString()
        } | ConvertTo-Json
        $meta | Set-Content (Join-Path $outputDir "status.json") -Force
    }
}

Invoke-ScubaRun

while ($true) {
    Write-Host "[scubagear] Next run in $intervalMin minutes"
    Start-Sleep -Seconds ($intervalMin * 60)
    Invoke-ScubaRun
}