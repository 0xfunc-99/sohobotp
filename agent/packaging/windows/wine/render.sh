#!/bin/sh
# Inside the Wine container: show the MSI's windows on a virtual display and take screenshots.
set -u
export DISPLAY=:99 WINEDEBUG=-all WINEDLLOVERRIDES="mscoree,mshtml="
Xvfb :99 -screen 0 1024x768x24 >/dev/null 2>&1 &
sleep 2
wineboot -i >/dev/null 2>&1
wine msiexec /i /agent/dist/sohobotp-agent.msi /l*v /out/msi.log >/dev/null 2>&1 &
shot() { import -window root "/out/$1.png"; echo "screenshot $1"; }
# wait for the setup window
for i in $(seq 1 60); do
  xdotool search --name "SohobOTP Agent Setup" >/dev/null 2>&1 && break
  sleep 2
done
sleep 3; shot 1-empty-form
win=$(xdotool search --name "SohobOTP Agent Setup" | head -1)
xdotool windowactivate --sync "$win" 2>/dev/null; sleep 1
xdotool type --delay 30 "https://192.168.10.5"; xdotool key Tab
xdotool type --delay 30 "a1b2c3d4e5f6.TEST-TOKEN-0123456789abcdefghi"; xdotool key Tab
xdotool type --delay 30 "34750f98bd59fcfc946da45aaabe933be154a4b5094e1c4abf42866505f3c97e"
sleep 2; shot 2-filled-form
xdotool key Return            # Install (default button)
sleep 25; shot 3-after-install
grep -E "Return value|SetupDlg|ProgressDlg|FinishDlg|FatalErrorDlg|PORTAL|Installation success|Installation failed" /out/msi.log | sed 's/\x0//g' | tail -15
