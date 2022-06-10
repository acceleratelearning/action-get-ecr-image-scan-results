#!/bin/env pwsh
[CmdletBinding()]
param (
    [String]$Registry,
    [String]$RepositoryName,
    [String]$MajorMinorVersion
)

$tag_pattern = "$($MajorMinorVersion.Replace('.','\.'))\.\d+"
$tags = (aws ecr list-images --repository-name $RepositoryName | ConvertFrom-Json).imageIds.imageTag
$greatest_tag = $tags | Where-Object { $_ -match $tag_pattern } | ForEach-Object { [Version]"$_" } | Sort-Object -Descending | Select-Object -First 1
if (-Not $greatest_tag) {
    $next_tag = [Version]"$($MajorMinorVersion).0"
}
else {
    $next_tag = [Version]::new($greatest_tag.Major, $greatest_tag.Minor, $greatest_tag.Build + 1)
}
$next_image_name = "$Registry/$($RepositoryName):$next_tag"
Write-Host "::set-output name=next-tag::$next_tag"
Write-Host "::set-output name=next-image-name::$next_image_name"
