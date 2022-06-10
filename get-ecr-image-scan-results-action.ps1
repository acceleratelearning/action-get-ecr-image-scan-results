#!/bin/env pwsh
[CmdletBinding()]
param (
    [String]$Registry,
    [String]$RepositoryName,
    [String]$Tag
)

Function ConvertTo-Markdown {
    [CmdletBinding()]
    [OutputType([string])]
    Param (
        [Parameter(
            Mandatory = $true,
            Position = 0,
            ValueFromPipeline = $true
        )]
        [PSObject[]]$InputObject
    )

    Begin {
        $items = @()
        $columns = @{}
    }

    Process {
        ForEach ($item in $InputObject) {
            $items += $item

            $item.PSObject.Properties | % {
                if ($_.Value -ne $null) {
                    if (-not $columns.ContainsKey($_.Name) -or $columns[$_.Name] -lt $_.Value.ToString().Length) {
                        $columns[$_.Name] = $_.Value.ToString().Length
                    }
                }
            }
        }
    }

    End {
        ForEach ($key in $($columns.Keys)) {
            $columns[$key] = [Math]::Max($columns[$key], $key.Length)
        }

        $header = @()
        ForEach ($key in $columns.Keys) {
            $header += ('{0,-' + $columns[$key] + '}') -f $key
        }
        $header -join ' | '

        $separator = @()
        ForEach ($key in $columns.Keys) {
            $separator += '-' * $columns[$key]
        }
        $separator -join ' | '

        ForEach ($item in $items) {
            $values = @()
            ForEach ($key in $columns.Keys) {
                $values += ('{0,-' + $columns[$key] + '}') -f $item.($key)
            }
            $values -join ' | '
        }
    }
}

aws ecr wait image-scan-complete --repository-name $RepositoryName --image-id imageTag=$tag
$scan_results = aws ecr describe-image-scan-findings --repository-name $RepositoryName --image-id imageTag=$tag | ConvertFrom-Json
if ($scan_results.imageScanFindings.findings.severity -contains 'HIGH' -or $scan_results.imageScanFindings.findings.severity -contains 'CRITICAL') {
    Write-Output "::notice:: Critical or High vulnerabilites found in image"
}

if ($scan_results.imageScanFindings.findings) {
    Write-Output "# ECR Container Image Scan Results" | Add-Content $env:GITHUB_STEP_SUMMARY
    $scan_results.imageScanFindings.findings `
    | Select-Object @{n = 'CVE'; e = { "[$($_.name)]($($_.uri))" } }, @{n = 'Severity'; e = { $_.severity } }, @{n = 'Description'; e = { $_.description.replace('|', '\|') } } `
    | ConvertTo-Markdown `
    | Add-Content $env:GITHUB_STEP_SUMMARY
}
