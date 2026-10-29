# Spore controls — the game's own bindings, and what the pad sends

Source: the official list at `spore.com/comm/tutorials/controls` (EA/Maxis, fetched 2026-10-29).

The important conclusion for a handheld port: **Spore is a mouse-driven game.** Almost every
action is a click, a drag or a wheel turn. The pad mapping therefore has to send mouse events,
not only keys.

## General

| Input | Action |
|---|---|
| W / A / S / D (or numpad 8/4/2/6) | move forward / left / back / right |
| Arrow keys | move camera, navigate menus |
| **Left mouse click** | go here / action / select / use tool — the primary verb |
| **Left mouse drag** | drive creature, ship, cell; rectangle-select in Tribe/Civ |
| **Right mouse click** | fly to / secondary action |
| **Right mouse drag** | pitch and rotate the camera |
| **Left+Right drag** | pitch and rotate (alternative) |
| Mouse wheel | zoom camera, change altitude, scale in editors |
| B | Sporepedia |
| H or ? | Sporeguide |
| L | mission log |
| T | timeline |
| P or ~ | pause |
| V / C | record movie / take picture |
| Ctrl+H | hide UI |
| Ctrl+S | save game or asset |
| Esc | deselect, close dialog, skip cinematic, options |
| Enter | accept (green checkmark) |

## Cell stage
Arrow keys move the avatar, **Backspace** is the mating call, LMB click to go/act.

## Creature stage
1–4 verb tray, arrows move, **E/Q** strafe right/left, **F** target nearest, **K** drop object,
**R** autorun, **Z** sneak, **Shift** sprint, **Space** jump (again to flap), **F1** super
ability, **Tab** verb tray, **Backspace** locating call.

## Tribe stage
1–4 verb tray, arrows move the camera, **F1/F2** super abilities, **Ctrl+A** select all,
**Tab** toggle verb tray, **Space** toggle group spacing, **Backspace** camera to hut.

## Civilization stage
1–4 verb tray, **Ctrl+0-9** assign group, arrows camera, **F1–F4** super abilities,
**Ctrl+A** select all, **Tab** vehicle stance, **Space** toggle units, **Delete** disband,
**Backspace** cycle cities.

## Space stage
1–9 tools, **Ctrl+1-9** second tool row, arrows camera, **E/Q** strafe, **R** rares,
**X** zoom ship in, **Space** zoom ship out, **Y** comm screen, **Tab / Shift+Tab** cycle
tools, **Backspace** return to home planet / centre on it.

## Editors
Mouse wheel scales, **Ctrl+N / Ctrl+Y / Ctrl+Z** new / redo / undo, **Tab** advanced handles,
**Delete** remove rigblock, **Alt+LMB** clone part, **Ctrl+LMB** break apart limbs,
**Shift+LMB** paint all regions, **Ctrl+Shift+LMB** paint similar regions.

---

# What the pad sends (`ports/spore/spore.gptk`)

| Pad | Sends | Why |
|---|---|---|
| **A** | left click | the primary verb; must be the easiest button to reach |
| **B** | right click | fly to / secondary action |
| **X** | Space | jump, flap, toggle units |
| **Y** | Tab | verb tray / tools palette |
| **L1 / R1** | Q / E | strafe left / right |
| **L2 / R2** | - / + | zoom out / in |
| **D-Pad** | arrow keys | camera and menu navigation |
| **Left stick** | W / A / S / D | movement |
| **Right stick** | mouse movement | camera rotation and aiming |
| **Start** | Enter | accept |
| **Select** | Esc | deselect / options |
| **Select + Start** | Esc | quit to the system menu |

## Known gaps in a keyboard/mouse mapping

1. **Two-button drags** (LMB+RMB) and **click-and-drag** selection need the stick and the click
   at the same time. GPTOKEYB can do it, but it is imprecise — that is inherent to emulating a
   mouse with a stick.
2. **Numpad-style movement** (8/4/2/6) is used by some screens; the D-Pad sends arrow keys
   instead, which covers the same navigation.

Both gaps disappear once the game reads a real gamepad: that is the `DInput8` layer's job, and
it is on the list after the renderer. Until then, keyboard/mouse emulation is what makes the
port usable at all.

## Not implemented yet

`DirectInput8Create` currently fails cleanly (`DIERR_DEVICENOTREG`), so the game takes its
no-input-device path. Nothing reads the pad directly.
