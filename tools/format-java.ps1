param([switch]$Check)
$ErrorActionPreference = 'Stop'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$toolDirectory = Join-Path $repositoryRoot '.tools'
$formatterPath = Join-Path $toolDirectory 'google-java-format-1.24.0.jar'
$expectedHash = '812f805f58112460edf01bf202a8e61d0fd1f35c0d4fabd54220640776ec57a1'
if (-not (Test-Path -LiteralPath $formatterPath)) {
    New-Item -ItemType Directory -Path $toolDirectory -Force | Out-Null
    Invoke-WebRequest -Uri 'https://github.com/google/google-java-format/releases/download/v1.24.0/google-java-format-1.24.0-all-deps.jar' -OutFile $formatterPath -UseBasicParsing
}
if ((Get-FileHash -LiteralPath $formatterPath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expectedHash) {
    throw 'Java formatter checksum mismatch.'
}
$javaCommand = 'java'
if (-not [string]::IsNullOrWhiteSpace($env:JAVA_HOME)) { $javaCommand = Join-Path $env:JAVA_HOME 'bin/java.exe' }
$sources = @(Get-ChildItem -LiteralPath (Join-Path $repositoryRoot 'app/src'), $PSScriptRoot -Filter '*.java' -Recurse | Select-Object -ExpandProperty FullName)
if ($Check) {
    & $javaCommand -jar $formatterPath --dry-run --set-exit-if-changed $sources
} else {
    & $javaCommand -jar $formatterPath --replace $sources
}
if ($LASTEXITCODE -ne 0) { throw 'Java formatting check failed.' }
