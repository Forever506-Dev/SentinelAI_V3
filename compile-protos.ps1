<#
.SYNOPSIS
    SentinelAI — Proto Compilation Script (Windows)

.DESCRIPTION
    Compiles .proto files into Python bindings using grpcio-tools.
    For buf-based compilation, install buf and run: buf generate

.PARAMETER CheckOnly
    Validate proto files without generating output (for CI).
#>

[CmdletBinding()]
param(
    [switch]$CheckOnly
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Push-Location $ProjectRoot

try {
    $PythonOut = "gen\python"
    New-Item -ItemType Directory -Force -Path $PythonOut | Out-Null

    # ── Try buf first ──────────────────────────────────────
    $bufPath = Get-Command buf -ErrorAction SilentlyContinue
    if ($bufPath) {
        Write-Host "[*] Using buf for proto compilation..." -ForegroundColor Green

        if ($CheckOnly) {
            buf lint
            buf build
            Write-Host "[✓] Proto validation passed." -ForegroundColor Green
            return
        }

        buf generate
        Write-Host "[✓] Proto files compiled via buf → $PythonOut" -ForegroundColor Green
        return
    }

    # ── Fallback to protoc via grpcio-tools ────────────────
    Write-Host "[*] Using grpcio-tools for proto compilation..." -ForegroundColor Green

    # Ensure grpcio-tools is installed
    python -m pip install grpcio-tools --quiet 2>$null

    # Compile v1 proto
    $v1Proto = "shared\proto\sentinel.proto"
    if (Test-Path $v1Proto) {
        if ($CheckOnly) {
            python -m grpc_tools.protoc --proto_path=shared/proto --python_out=$env:TEMP $v1Proto
            Write-Host "[✓] sentinel.proto (v1) compiles" -ForegroundColor Green
        }
        else {
            python -m grpc_tools.protoc `
                --proto_path=shared/proto `
                --python_out=$PythonOut `
                --grpc_python_out=$PythonOut `
                --pyi_out=$PythonOut `
                $v1Proto
            Write-Host "[✓] sentinel.proto (v1) → $PythonOut" -ForegroundColor Green
        }
    }

    # Compile v2 proto
    $v2Proto = "docs\architecture\proto\sentinel_v2.proto"
    if (Test-Path $v2Proto) {
        if ($CheckOnly) {
            python -m grpc_tools.protoc --proto_path=docs/architecture/proto --python_out=$env:TEMP $v2Proto
            Write-Host "[✓] sentinel_v2.proto (v2) compiles" -ForegroundColor Green
        }
        else {
            python -m grpc_tools.protoc `
                --proto_path=docs/architecture/proto `
                --python_out=$PythonOut `
                --grpc_python_out=$PythonOut `
                --pyi_out=$PythonOut `
                $v2Proto
            Write-Host "[✓] sentinel_v2.proto (v2) → $PythonOut" -ForegroundColor Green
        }
    }

    if (-not $CheckOnly) {
        # Create __init__.py
        New-Item -ItemType File -Force -Path "$PythonOut\__init__.py" | Out-Null
        Write-Host "[✓] Generated Python proto package at $PythonOut" -ForegroundColor Green
    }

    Write-Host ""
    Write-Host "[✓] Proto compilation complete." -ForegroundColor Green
}
finally {
    Pop-Location
}
