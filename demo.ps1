$ErrorActionPreference = 'Stop'
Push-Location $PSScriptRoot
try {
    # Work in a fresh, owned directory inside this checkout; source/build stay intact.
    $demoDirectory = Join-Path $PSScriptRoot ('build/demo-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $demoDirectory | Out-Null
    $oldExpected = [Environment]::GetEnvironmentVariable('JAVELIN_EXPECTED_SHA256')
    try {
        Write-Output 'C++: finalized executable'
        & ./build/AntiCheat.exe --verify-integrity
        if ($LASTEXITCODE -ne 0) { throw 'Expected finalized executable to pass' }
        $changedExe = Join-Path $demoDirectory 'changed.exe'
        $bytes = [IO.File]::ReadAllBytes((Join-Path $PSScriptRoot 'build/AntiCheat.exe'))
        $bytes[$bytes.Length - 1] = $bytes[$bytes.Length - 1] -bxor 1
        [IO.File]::WriteAllBytes($changedExe, $bytes)
        Write-Output 'C++: one changed byte in a temporary copy'
        & $changedExe --verify-integrity
        Write-Output "Observed exit status: $LASTEXITCODE (expected 3)"
        if ($LASTEXITCODE -ne 3) { throw 'Expected modified executable to fail' }
        $changedScript = Join-Path $demoDirectory 'AntiCheat.py'
        Copy-Item -LiteralPath ./AntiCheat.py -Destination $changedScript
        $env:JAVELIN_EXPECTED_SHA256 = (Get-FileHash -LiteralPath $changedScript -Algorithm SHA256).Hash
        Write-Output 'Python: matching trusted SHA-256'
        python $changedScript
        if ($LASTEXITCODE -ne 0) { throw 'Expected matching script to pass' }
        [IO.File]::AppendAllText($changedScript, "`n# demonstration change`n")
        Write-Output 'Python: changed temporary script, unchanged expected SHA-256'
        python $changedScript
        Write-Output "Observed exit status: $LASTEXITCODE (expected 3)"
        if ($LASTEXITCODE -ne 3) { throw 'Expected modified script to fail' }
    } finally {
        [Environment]::SetEnvironmentVariable('JAVELIN_EXPECTED_SHA256', $oldExpected)
        # Absolute target was created here under this checkout's build directory.
        $resolvedDemo = [IO.Path]::GetFullPath($demoDirectory)
        $buildRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'build')) + [IO.Path]::DirectorySeparatorChar
        if (!$resolvedDemo.StartsWith($buildRoot, [StringComparison]::OrdinalIgnoreCase)) { throw 'Unexpected demo cleanup path' }
        Remove-Item -LiteralPath $resolvedDemo -Recurse -Force
    }
} finally { Pop-Location }
