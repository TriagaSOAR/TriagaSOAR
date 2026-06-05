$tenantId     = $env:MAESTER_TENANT_ID
$clientId     = $env:MAESTER_CLIENT_ID
$clientSecret = $env:MAESTER_CLIENT_SECRET
$intervalMin  = [int]($env:MAESTER_INTERVAL_MINUTES ?? "60")
$outputDir    = $env:MAESTER_OUTPUT_DIR ?? "/app/output"
$testsDir     = "/app/tests"

if (-not $tenantId -or -not $clientId -or -not $clientSecret) {
    Write-Error "[maester] MAESTER_TENANT_ID, MAESTER_CLIENT_ID, MAESTER_CLIENT_SECRET must be set"
    exit 1
}

function Ensure-Tests {
    if (-not (Test-Path $testsDir) -or (Get-ChildItem $testsDir -Filter "*.Tests.ps1" -Recurse).Count -eq 0) {
        Write-Host "[maester] Downloading Maester tests..."
        New-Item -ItemType Directory -Path $testsDir -Force | Out-Null
        Set-Location $testsDir
        Install-MaesterTests -Path $testsDir
        Write-Host "[maester] Tests installed"
    } else {
        Write-Host "[maester] Tests already present"
    }
}

function Invoke-MaesterRun {
    Write-Host "[maester] Starting run at $(Get-Date -Format 'o')"

    try {
        $secureSecret = ConvertTo-SecureString $clientSecret -AsPlainText -Force
        $credential   = New-Object System.Management.Automation.PSCredential($clientId, $secureSecret)

        Connect-MgGraph `
            -TenantId $tenantId `
            -ClientSecretCredential $credential `
            -NoWelcome

        Write-Host "[maester] Connected to Microsoft Graph"

        Ensure-Tests

        $timestamp  = Get-Date -Format "yyyyMMdd-HHmmss"
        $reportPath = Join-Path $outputDir "maester-$timestamp"
        New-Item -ItemType Directory -Path $reportPath -Force | Out-Null

        Set-Location $testsDir

        Invoke-Maester `
            -Path $testsDir `
            -OutputFolder $reportPath `
            -NonInteractive

        $jsonFile = Get-ChildItem -Path $reportPath -Filter "*.json" -Recurse |
                    Sort-Object LastWriteTime -Descending |
                    Select-Object -First 1

        if ($jsonFile) {
            $latestPath = Join-Path $outputDir "latest.json"
            Copy-Item -Path $jsonFile.FullName -Destination $latestPath -Force
            Write-Host "[maester] Report written to $latestPath"

            $meta = @{
                last_run    = (Get-Date -Format "o")
                report_file = $jsonFile.Name
                report_path = $reportPath
                status      = "success"
            } | ConvertTo-Json
            $meta | Set-Content (Join-Path $outputDir "status.json") -Force
        } else {
            Write-Warning "[maester] No JSON output found in $reportPath"
            $meta = @{
                last_run = (Get-Date -Format "o")
                status   = "no_output"
            } | ConvertTo-Json
            $meta | Set-Content (Join-Path $outputDir "status.json") -Force
        }

        Disconnect-MgGraph | Out-Null
    } catch {
        Write-Error "[maester] Run failed: $_"
        $meta = @{
            last_run = (Get-Date -Format "o")
            status   = "error"
            error    = $_.ToString()
        } | ConvertTo-Json
        $meta | Set-Content (Join-Path $outputDir "status.json") -Force
    }
}

Invoke-MaesterRun

while ($true) {
    Write-Host "[maester] Next run in $intervalMin minutes"
    Start-Sleep -Seconds ($intervalMin * 60)
    Invoke-MaesterRun
}