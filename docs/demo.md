# Integrity verification demo

[Watch the 30-second demo](integrity-demo.mp4) (download if your viewer does not
play repository MP4 files).

The video renders the actual captured output of `demo.ps1` and the build/test
run; it is a transcript walkthrough, not a desktop recording. No results are
simulated. The trusted executable and script pass, while temporary copies with
changed bytes fail with exit status 3. See [demo output](demo-output.txt) and
[full build/test output](verification-output.txt).

To reproduce, build with `./build.ps1 -RunTests`, then run `./demo.ps1` from
PowerShell. The captured run used Windows x86-64, Python 3.12 and Zig 0.15.2.
The native CRC reference checks and all eight Python/native integration tests
passed, with no skipped tests.
