$ErrorActionPreference = 'Stop'
Push-Location (Split-Path -Parent $PSScriptRoot)
try {
    $labPython = $null
    $labPrefix = @()
    # Prefer native 3.11+, then native 3.10. Never installs anything.
    foreach ($candidate in @('py', 'python')) {
        if (-not (Get-Command $candidate -ErrorAction SilentlyContinue)) { continue }
        $candidatePrefix = @()
        if ($candidate -eq 'py') { $candidatePrefix = @('-3') }
        & $candidate @candidatePrefix -c 'import sys; sys.exit(0 if sys.version_info >= (3,11) else 1)' 2>$null
        if ($LASTEXITCODE -eq 0) {
            $labPython = $candidate
            $labPrefix = $candidatePrefix
            break
        }
    }
    if (-not $labPython) {
        foreach ($candidate in @('python', 'py')) {
            if (-not (Get-Command $candidate -ErrorAction SilentlyContinue)) { continue }
            & $candidate -c 'import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)' 2>$null
            if ($LASTEXITCODE -eq 0) { $labPython = $candidate; break }
        }
    }
    if (-not $labPython) { throw 'No native Python 3.10+ found. Stop and inspect environment; no software installed.' }
    & $labPython @labPrefix --version
    & $labPython @labPrefix -m unittest discover -v
    if ($LASTEXITCODE -ne 0) { throw 'Unit tests failed.' }
    & $labPython @labPrefix -m lab.demo
    if ($LASTEXITCODE -ne 0) { throw 'Demo failed.' }
} finally {
    Pop-Location
}
