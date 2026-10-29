#!/bin/bash
# Spore — muOS / RG 35 XX H launcher.
#
# Follows the layout of the working NFSU2 port:
#   /roms/ports/spore.sh          this script
#   /roms/ports/spore/            the port folder
#       spore                     the binary
#       spore.cfg                 settings (optional)
#       spore.gptk                gamepad profile
#       port.json                 PortMaster metadata
#       gamedata/                 YOUR retail game files
#
# On muOS the SD card is mounted at /mnt/mmc, and PortMaster data lives in a union mount,
# so the script looks for the port folder in every place muOS and ArkOS are known to use.

XDG_DATA_HOME=${XDG_DATA_HOME:-$HOME/.local/share}

if [ -d "/opt/system/Tools/PortMaster/" ]; then
  controlfolder="/opt/system/Tools/PortMaster"
elif [ -d "/opt/tools/PortMaster/" ]; then
  controlfolder="/opt/tools/PortMaster"
elif [ -d "$XDG_DATA_HOME/PortMaster/" ]; then
  controlfolder="$XDG_DATA_HOME/PortMaster"
else
  controlfolder="/roms/ports/PortMaster"
fi

if [ -f "$controlfolder/control.txt" ]; then
  . "$controlfolder/control.txt"
  [ -f "${controlfolder}/mod_${CFW_NAME}.txt" ] && . "${controlfolder}/mod_${CFW_NAME}.txt"
  get_controls
fi

ESUDO="${ESUDO:-sudo}"
CURR_TTY="/dev/tty1"
[ -e "$CURR_TTY" ] && exec < "$CURR_TTY"

SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"

# muOS mounts the SD card at /mnt/mmc and exposes port data through /mnt/union.
# The .sh may live in ROMS/Ports while the folder sits in ports/ (muOS splits them), so both
# the sibling layout and the muOS layout are tried.
for cand in \
  "/mnt/union/ports/spore" \
  "/mnt/union/ports/Spore" \
  "/mnt/mmc/ports/spore" \
  "/mnt/mmc/ports/Spore" \
  "/mnt/sdcard/ports/spore" \
  "/mnt/sdcard/ports/Spore" \
  "/roms/ports/spore" \
  "/roms/ports/Spore" \
  "$SCRIPT_DIR/spore" \
  "$SCRIPT_DIR/Spore" \
  "$SCRIPT_DIR/../ports/spore" \
  "$SCRIPT_DIR/../ports/Spore"
do
  if [ -f "$cand/spore" ]; then
    GAMEDIR="$cand"
    break
  fi
done

if [ -z "${GAMEDIR:-}" ]; then
  printf "\033c" > "$CURR_TTY" 2>/dev/null || true
  echo "ERROR: the Spore port folder was not found."
  echo "Expected the binary at one of:"
  echo "  /mnt/mmc/ports/Spore/spore"
  echo "  /roms/ports/spore/spore"
  echo "  $SCRIPT_DIR/spore/spore"
  sleep 8
  exit 1
fi

cd "$GAMEDIR" || exit 1

export LD_LIBRARY_PATH="$GAMEDIR/libs:$LD_LIBRARY_PATH"
[ -n "$sdl_controllerconfig" ] && export SDL_GAMECONTROLLERCONFIG="$sdl_controllerconfig"

# Graphics environment as used by the working muOS ports: do not force kmsdrm.
unset SDL_VIDEODRIVER
export SDL_AUDIODRIVER=alsa
export ALSOFT_DRIVERS=alsa
export SDL_VIDEO_GL_DRIVER=libGLESv2.so
export SDL_VIDEO_EGL_DRIVER=libEGL.so
export MALLOC_CHECK_=0

# Settings.
[ -f "$GAMEDIR/spore.cfg" ] && . "$GAMEDIR/spore.cfg"

ARGS="$GAMEDIR/gamedata"
[ "${SPORE_VERBOSE:-0}" = "1" ] && ARGS="$ARGS --verbose"
[ "${SPORE_TRACE:-0}" = "1" ] && ARGS="$ARGS --trace-imports"

# --- verify the guest executable ------------------------------------------
EXE=""
for cand in "$GAMEDIR/gamedata/SporeApp.exe" \
            "$GAMEDIR/gamedata/sporeapp.exe" \
            "$GAMEDIR/gamedata/Spore/SporeApp.exe" \
            "$GAMEDIR/SporeApp.exe"; do
  [ -f "$cand" ] && { EXE="$cand"; break; }
done

if [ -z "$EXE" ]; then
  printf "\033c" > "$CURR_TTY" 2>/dev/null || true
  echo "ERROR: SporeApp.exe not found in $GAMEDIR/gamedata/"
  echo ""
  echo "Copy your retail Spore installation there:"
  echo "  $GAMEDIR/gamedata/SporeApp.exe"
  echo "  $GAMEDIR/gamedata/Data/*.package"
  sleep 8
  exit 1
fi

# The recompilation is built against one specific executable build. If the size does not
# match, say so plainly instead of crashing somewhere inside the loader.
EXESIZE=$(stat -c%s "$EXE" 2>/dev/null || wc -c < "$EXE" | tr -d ' ')
SUPPORTED="24895528 25066744 20626168"
case " $SUPPORTED " in
  *" $EXESIZE "*) : ;;
  *)
    printf "\033c" > "$CURR_TTY" 2>/dev/null || true
    echo "WARNING: SporeApp.exe is $EXESIZE bytes."
    echo "This build was lifted from the 24,895,528-byte Galactic Adventures executable."
    echo "A different build will load but may fail; the log will say where."
    sleep 5
    ;;
esac

chmod 755 "$GAMEDIR/spore" 2>/dev/null || true

# --- run -------------------------------------------------------------------
printf "\033c" > "$CURR_TTY" 2>/dev/null || true
printf "\e[?25l" > "$CURR_TTY" 2>/dev/null || true
echo 0 | $ESUDO tee /sys/class/vtconsole/vtcon0/bind >/dev/null 2>&1 || true
echo 0 | $ESUDO tee /sys/class/vtconsole/vtcon1/bind >/dev/null 2>&1 || true

[ -f "$GAMEDIR/log.txt" ] && mv -f "$GAMEDIR/log.txt" "$GAMEDIR/log.prev.txt"

{
  echo "[launcher] $(date)"
  free -m
  uname -a
  for f in /sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq /sys/class/devfreq/*/cur_freq; do
    [ -f "$f" ] && echo "[launcher] $f = $(cat "$f" 2>/dev/null)"
  done
} > "$GAMEDIR/launcher.log" 2>&1

echo "[launcher] port dir: $GAMEDIR" > "$GAMEDIR/log.txt"
echo "[launcher] guest exe: $EXE ($EXESIZE bytes)" >> "$GAMEDIR/log.txt"
echo "[launcher] running: ./spore $ARGS" >> "$GAMEDIR/log.txt"

"./spore" $ARGS >> "$GAMEDIR/log.txt" 2>&1
EXIT_CODE=$?

sync

echo 1 | $ESUDO tee /sys/class/vtconsole/vtcon0/bind >/dev/null 2>&1 || true
echo 1 | $ESUDO tee /sys/class/vtconsole/vtcon1/bind >/dev/null 2>&1 || true
$ESUDO systemctl restart oga_events >/dev/null 2>&1 &
printf "\033c" > "$CURR_TTY" 2>/dev/null || true
printf "\e[?25h" > "$CURR_TTY" 2>/dev/null || true

exit "$EXIT_CODE"
