param(
    [string]$Compiler = 'cl',
    [uint32]$ExpectedCrc = 3235782694,
    [switch]$RunTests
)
$ErrorActionPreference = 'Stop'
Push-Location $PSScriptRoot
try {
    if ($ExpectedCrc -eq 0) { throw 'Choose a nonzero CRC for a guarded build.' }
    New-Item -ItemType Directory -Force build | Out-Null
    $constant = '0x{0:X8}u' -f $ExpectedCrc
    function Build-Native($source, $output, $baseline) {
        if ([IO.Path]::GetFileNameWithoutExtension($Compiler) -eq 'zig') {
            & $Compiler c++ -target x86_64-windows-gnu -std=c++17 -O2 "-DJAVELIN_EXPECTED_CRC32=$baseline" $source -o $output
        } else {
            & $Compiler /nologo /EHsc /std:c++17 /O2 "/DJAVELIN_EXPECTED_CRC32=$baseline" $source "/Fe:$output" /Fo:build/
        }
        if ($LASTEXITCODE -ne 0) { throw "Compilation failed: $source" }
    }
    Build-Native AntiCheat.cpp build/AntiCheat.exe $constant
    Copy-Item -LiteralPath build/AntiCheat.exe -Destination build/AntiCheat-unfinalized.exe
    python tools/finalize_crc32.py build/AntiCheat.exe ('0x{0:X8}' -f $ExpectedCrc)
    if ($LASTEXITCODE -ne 0) { throw 'CRC finalization failed' }
    & ./build/AntiCheat.exe --verify-integrity
    if ($LASTEXITCODE -ne 0) { throw 'Finalized executable failed its own integrity check' }
    if ($RunTests) {
        Build-Native AntiCheat.cpp build/AntiCheat-disabled.exe '0u'
        Build-Native tests/integrity_tests.cpp build/integrity_tests.exe '0u'
        & ./build/integrity_tests.exe
        if ($LASTEXITCODE -ne 0) { throw 'Native unit tests failed' }
        $oldTestEnv = @{}
        foreach ($name in @('JAVELIN_TEST_EXE', 'JAVELIN_TEST_UNFINALIZED_EXE', 'JAVELIN_TEST_DISABLED_EXE')) {
            $oldTestEnv[$name] = [Environment]::GetEnvironmentVariable($name)
        }
        try {
            $env:JAVELIN_TEST_EXE = (Resolve-Path build/AntiCheat.exe).Path
            $env:JAVELIN_TEST_UNFINALIZED_EXE = (Resolve-Path build/AntiCheat-unfinalized.exe).Path
            $env:JAVELIN_TEST_DISABLED_EXE = (Resolve-Path build/AntiCheat-disabled.exe).Path
            python -m unittest discover -s tests -v
            if ($LASTEXITCODE -ne 0) { throw 'Python/native integration tests failed' }
        } finally {
            foreach ($name in $oldTestEnv.Keys) { [Environment]::SetEnvironmentVariable($name, $oldTestEnv[$name]) }
        }
    }
} finally { Pop-Location }
