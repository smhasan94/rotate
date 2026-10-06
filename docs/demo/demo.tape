# The README demo (SHA-340), rendered with charmbracelet vhs.
#
# From the repository root:
#
#   cargo build --features test-providers
#   ROTATE_BIN=$PWD/target/debug/rotate vhs docs/demo/demo.tape
#
# scripts/demo.sh does all the work: a simulated rotation with the
# test-providers build (mock AWS, GitHub Actions and Secrets Manager, a fake
# key made at run time, no credentials, no network). DEMO_PACE paces it and
# clears the screen between steps. Keep docs/demo/demo.gif under 2 MB:
# lower Framerate, then Width and Height, if a render is bigger.

Output docs/demo/demo.gif

Require bash

Set Shell "bash"
Set FontSize 14
Set Width 1180
Set Height 660
Set Padding 20
Set Framerate 12
Set TypingSpeed 40ms

Env DEMO_PACE "3"

Hide
Type "export PS1='$ ' ROTATE_BIN=${ROTATE_BIN:-$PWD/target/debug/rotate}; clear; scripts/demo.sh"
Enter
Show

Sleep 22s
