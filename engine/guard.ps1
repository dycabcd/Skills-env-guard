param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet('check', 'init', 'run', 'inspect')]
    [string]$Command,

    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Remaining
)

$ErrorActionPreference = 'Stop'
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$python = $env:ENVGUARD_PYTHON

if (-not $python) {
    $venvPython = Join-Path (Split-Path -Parent (Split-Path -Parent $scriptDir)) '.venv\Scripts\python.exe'
    if (Test-Path $venvPython) {
        $python = $venvPython
    } elseif (Get-Command python -ErrorAction SilentlyContinue) {
        $python = 'python'
    } elseif (Get-Command py -ErrorAction SilentlyContinue) {
        $python = 'py'
    }
}

if (-not $python) {
    Write-Error '[env-guard:NOT_FOUND] Python 3 is required'
    exit 12
}

$engine = Join-Path $scriptDir 'guard.py'
& $python $engine $Command @Remaining
exit $LASTEXITCODE
