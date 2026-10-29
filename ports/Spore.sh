#!/bin/bash
# Spore — muOS / RG 35 XX H launcher.
#
# Same shape as the working NFSU2 port launcher: locate PortMaster, set up the SDL/graphics
# environment muOS expects, verify the game data, run, and restore the console afterwards.
#
# Options come from spore.cfg (all optional):
#   SPORE_RENDER=854x480      exact render size
#   SPORE_SCREEN=640x480      panel size, if detection is wrong
#   SPORE_RENDER_SCALE=0.75   render below panel resolution and upscale
#   SPORE_ROTATE=90|270       portrait-mounted panel
#   SPORE_VERBOSE=1           log every guest import call
#   SPORE_TRACE=1             log the first call of every import

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

# muOS uses a union mount for port data; keep the known paths supported.
if [ -d "/mnt/union/ports/spore" ]; then
  GAMEDIR="/mnt/union/ports/spore"
elif [ -d "/mnt/sdcard/ports/spore" ]; then
  GAMEDIR="/mnt/sdcard/ports/spore"
elif [ -n "$directory" ] && [ -d "/$directory/ports/spore" ]; then
  GAMEDIR="/$directory/ports/spore"
elif [ -d "$SCRIPT_DIR/spore" ]; then
  GAMEDIR="$SCRIPT_DIR/spore"
else
  echo "ERROR: Spore port directory not found."
  sleep 5
  exit 1
fi

cd "$GAMEDIR" || exit 1

export LD_LIBRARY_PATH="$GAMEDIR/libs:$LD_LIBRARY_PATH"
[ -n "$sdl_controllerconfig" ] && export SDL_GAMECONTROLLERCONFIG="$sdl_controllerconfig"

# Graphics environment as used by the working muOS ports.
unset SDL_VIDEODRIVER
export SDL_AUDIODRIVER=alsa
export ALSOFT_DRIVERS=alsa
export SDL_VIDEO_GL_DRIVER=libGLESv2.so
export SDL_VIDEO_EGL_DRIVER=libEGL.so
export MALLOC_CHECK_=0

[ -f "$GAMEDIR/spore.cfg" ] && . "$GAMEDIR/spore.cfg"

ARGS="$GAMEDIR/gamedata"
[ -n "${SPORE_RENDER:-}" ] && export SPORE_RENDER
[ -n "${SPORE_SCREEN:-}" ] && export SPORE_SCREEN
[ -n "${SPORE_RENDER_SCALE:-}" ] && export SPORE_RENDER_SCALE
[ -n "${SPORE_ROTATE:-}" ] && export SPORE_ROTATE
[ "${SPORE_VERBOSE:-0}" = "1" ] && ARGS="$ARGS --verbose"
[ "${SPORE_TRACE:-0}" = "1" ] && ARGS="$ARGS --trace-imports"

# Verify the guest executable.
if [ ! -f "$GAMEDIR/gamedata/SporeApp.exe" ]; then
  printf "\033c" > "$CURR_TTY" 2>/dev/null || true
  echo "ERROR: SporeApp.exe not found in $GAMEDIR/gamedata/"
  echo "Copy your retail Spore installation (SporeApp.exe + Data/) there."
  sleep 6
  exit 1
fi

chmod 755 "$GAMEDIR/spore" 2>/dev/null || true

# Unbind the VT consoles so we get direct access to the framebuffer/DRM.
printf "\033c" > "$CURR_TTY" 2>/dev/null || true
printf "\e[?25l" > "$CURR_TTY" 2>/dev/null || true
echo 0 | $ESUDO tee /sys/class/vtconsole/vtcon0/bind >/dev/null 2>&1 || true
echo 0 | $ESUDO tee /sys/class/vtconsole/vtcon1/bind >/dev/null 2>&1 || true

# Keep the previous log, then start a new one.
[ -f "$GAMEDIR/log.txt" ] && mv -f "$GAMEDIR/log.txt" "$GAMEDIR/log.prev.txt"

{
  echo "[launcher] $(date)"
  free -m
  uname -a
} > "$GAMEDIR/launcher.log" 2>&1

echo "[launcher] running: ./spore $ARGS" >> "$GAMEDIR/log.txt"
"./spore" $ARGS >> "$GAMEDIR/log.txt" 2>&1
EXIT_CODE=$?

sync

# Restore the console and PortMaster's input daemon.
echo 1 | $ESUDO tee /sys/class/vtconsole/vtcon0/bind >/dev/null 2>&1 || true
echo 1 | $ESUDO tee /sys/class/vtconsole/vtcon1/bind >/dev/null 2>&1 || true
$ESUDO systemctl restart oga_events >/dev/null 2>&1 &
printf "\033c" > "$CURR_TTY" 2>/dev/null || true
printf "\e[?25h" > "$CURR_TTY" 2>/dev/null || true

exit "$EXIT_CODE"
