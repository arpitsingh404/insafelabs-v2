#!/usr/bin/env python3
"""
InsafeLabs — Native PC Gesture Control (PRO, config-driven)
===========================================================
Control your WHOLE computer with hand gestures via your webcam. Runs on YOUR
machine at the OS level, so (unlike the in-browser deck) it is NOT limited to a
single web page. Every gesture is fully re-mappable through a JSON config, so
you can bind fist / victory / any gesture to your OWN apps, hotkeys, text,
media keys, screenshots and more.

QUICK START
-----------
    pip install opencv-python mediapipe pyautogui numpy
    python insafelabs_pc_control.py

On first run it writes a config file next to the script:
    insafelabs_gestures.json
Edit that file to bind gestures to whatever you want, then press  r  in the
camera window to hot-reload it (or restart).

Linux extras:  sudo apt install scrot python3-tk python3-dev
macOS:  System Settings -> Privacy & Security -> grant Terminal Accessibility + Camera.

IN-WINDOW KEYS
--------------
    q / Esc = quit      p = pause/resume control      r = reload config
    h = toggle HUD help

SAFETY
------
    PyAutoGUI fail-safe is ON — slam the mouse into the TOP-LEFT screen corner
    to instantly abort. This tool is for controlling YOUR OWN computer.

SUPPORTED GESTURES (bindable keys in the config "bindings" object)
------------------------------------------------------------------
    fist, open_palm, point, victory, three, four, pinky, rock (index+pinky),
    call_me (thumb+pinky / shaka), l_shape (thumb+index), spiderman
    (thumb+index+pinky), thumb_up, thumb_down, pinch (thumb+index touch),
    pinch_hold (pinch held = drag)

SUPPORTED ACTIONS (the "action" field inside a binding)
-------------------------------------------------------
    click            {"action":"click","button":"left|right|middle"}
    double_click     {"action":"double_click"}
    drag             {"action":"drag"}                (best on pinch_hold)
    scroll           {"action":"scroll","amount":1}   (+up / -down, accelerates)
    hotkey           {"action":"hotkey","keys":"ctrl+alt+t"}
    press            {"action":"press","key":"enter"}
    type             {"action":"type","text":"hello world"}
    media            {"action":"media","key":"playpause|next|prev|volup|voldown|mute"}
    launch           {"action":"launch","app":"notepad"}   (win: notepad, mac: app name, linux: binary)
    screenshot       {"action":"screenshot","dir":"~/Pictures"}
    window           {"action":"window","op":"minimize|maximize|close|switch|show_desktop"}
    pause_toggle     {"action":"pause_toggle"}
    none             {"action":"none"}
Most discrete actions default to "hold":true (fire only after you hold the
gesture ~1s) so you don't trigger them by accident. Add "hold":false to fire
instantly on the gesture.
"""

import sys
import os
import json
import time
import math
import argparse
import subprocess
from datetime import datetime

try:
    import cv2
    import numpy as np
    import mediapipe as mp
    import pyautogui
except ImportError as exc:  # pragma: no cover
    print("\n[!] Missing a dependency:", exc)
    print("    Run:  pip install opencv-python mediapipe pyautogui numpy\n")
    sys.exit(1)


# ----------------------------------------------------------------- default config
DEFAULT_CONFIG = {
    "settings": {
        "camera": 0,
        "edge_reach": 0.18,          # 0..0.35 — shrink active region so small moves reach screen edges
        "smoothing": 0.35,           # 0.1 (buttery) .. 0.9 (snappy)
        "pinch_threshold": 0.055,    # thumb-index touch distance for a "pinch"
        "hold_seconds": 1.0,         # how long a gesture must be held to fire a "hold" action
        "cooldown_seconds": 1.5,     # min gap between two hold-fires
        "scroll_speed": 1.0,         # multiplier for thumb up/down scrolling
        "mirror": True,              # mirror the camera (natural)
        "move_cursor": True,         # index fingertip always moves the mouse
        "start_paused": False,
        "max_hands": 1,
    },
    "bindings": {
        "pinch":      {"action": "click", "button": "left", "hold": False},
        "pinch_hold": {"action": "drag", "hold": False},
        "thumb_up":   {"action": "scroll", "amount": 1, "hold": False},
        "thumb_down": {"action": "scroll", "amount": -1, "hold": False},
        "open_palm":  {"action": "click", "button": "right", "hold": True},
        "fist":       {"action": "screenshot", "dir": "~/Pictures", "hold": True},
        "victory":    {"action": "window", "op": "switch", "hold": True},
        "three":      {"action": "hotkey", "keys": "ctrl+c", "hold": True},
        "four":       {"action": "media", "key": "playpause", "hold": True},
        "pinky":      {"action": "media", "key": "volup", "hold": True},
        "rock":       {"action": "media", "key": "voldown", "hold": True},
        "call_me":    {"action": "launch", "app": "notepad", "hold": True},
        "l_shape":    {"action": "hotkey", "keys": "ctrl+v", "hold": True},
        "spiderman":  {"action": "pause_toggle", "hold": True},
    },
}

MEDIA_KEYS = {
    "playpause": "playpause", "play": "playpause", "pause": "playpause",
    "next": "nexttrack", "prev": "prevtrack", "previous": "prevtrack",
    "volup": "volumeup", "voldown": "volumedown", "mute": "volumemute",
}


def cfg_path(explicit=None):
    if explicit:
        return os.path.abspath(os.path.expanduser(explicit))
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(here, "insafelabs_gestures.json")


def load_config(path):
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))  # deep copy
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                user = json.load(f)
            for k, v in (user.get("settings") or {}).items():
                cfg["settings"][k] = v
            if isinstance(user.get("bindings"), dict):
                for g, b in user["bindings"].items():
                    cfg["bindings"][g] = b
            print(f"[+] Loaded config: {path}")
        except Exception as e:
            print(f"[!] Bad config ({e}); using defaults.")
    else:
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(DEFAULT_CONFIG, f, indent=2)
            print(f"[+] Wrote a default config you can edit: {path}")
        except Exception as e:
            print(f"[!] Could not write config: {e}")
    return cfg


# ----------------------------------------------------------------- helpers
def clamp01(v):
    return max(0.0, min(1.0, v))


def remap_reach(v, margin):
    if margin <= 0:
        return v
    return clamp01((v - margin) / (1.0 - 2.0 * margin))


def dist(a, b):
    return math.hypot(a[0] - b[0], a[1] - b[1])


def finger_states(lm):
    """[thumb, index, middle, ring, pinky] extended booleans."""
    up = [abs(lm[4][0] - lm[17][0]) > abs(lm[3][0] - lm[17][0])]
    for t, p in zip([8, 12, 16, 20], [6, 10, 14, 18]):
        up.append(lm[t][1] < lm[p][1])
    return up


def classify(lm):
    thumb, index, middle, ring, pinky = finger_states(lm)
    o = [index, middle, ring, pinky]
    if not any([thumb] + o):
        return "fist"
    if all([thumb] + o):
        return "open_palm"
    if index and middle and ring and pinky and not thumb:
        return "four"
    if index and middle and ring and not pinky:
        return "three"
    if index and middle and not ring and not pinky:
        return "victory"
    if index and pinky and not middle and not ring and not thumb:
        return "rock"
    if thumb and index and pinky and not middle and not ring:
        return "spiderman"
    if thumb and pinky and not index and not middle and not ring:
        return "call_me"
    if thumb and index and not middle and not ring and not pinky:
        return "l_shape"
    if index and not middle and not ring and not pinky:
        return "point"
    if pinky and not index and not middle and not ring:
        return "pinky"
    if thumb and not any(o):
        return "thumb_up" if lm[4][1] < lm[0][1] else "thumb_down"
    return "other"


# ----------------------------------------------------------------- main
class Controller:
    def __init__(self, cfg):
        self.cfg = cfg
        self.paused = bool(cfg["settings"].get("start_paused"))
        self.screen_w, self.screen_h = pyautogui.size()
        self.cur_x, self.cur_y = pyautogui.position()
        self.pinch_down = False
        self.dragging = False
        self.pinch_start = 0.0
        self.scroll_accel = 0
        self.hold_label = None
        self.hold_start = 0.0
        self.cooldown_until = 0.0
        self.last_action = "—"

    # -- action executor ----------------------------------------------------
    def run_action(self, binding):
        a = (binding or {}).get("action", "none")
        try:
            if a == "click":
                pyautogui.click(button=binding.get("button", "left"))
            elif a == "double_click":
                pyautogui.doubleClick()
            elif a == "hotkey":
                keys = [k for k in str(binding.get("keys", "")).replace(" ", "").split("+") if k]
                if keys:
                    pyautogui.hotkey(*keys)
            elif a == "press":
                pyautogui.press(binding.get("key", "enter"))
            elif a == "type":
                pyautogui.write(str(binding.get("text", "")), interval=0.01)
            elif a == "media":
                key = MEDIA_KEYS.get(binding.get("key", "playpause"), "playpause")
                pyautogui.press(key)
            elif a == "launch":
                self._launch(binding.get("app", ""))
            elif a == "screenshot":
                self._screenshot(binding.get("dir", "~"))
            elif a == "window":
                self._window(binding.get("op", "minimize"))
            elif a == "pause_toggle":
                self.paused = not self.paused
            self.last_action = f"{a}"
            print(f"    [action] {a} {binding}")
        except Exception as e:  # pragma: no cover
            print(f"    [action error] {a}: {e}")

    def _launch(self, app):
        if not app:
            return
        if sys.platform.startswith("win"):
            try:
                os.startfile(app)  # noqa
            except Exception:
                subprocess.Popen(app, shell=True)
        elif sys.platform == "darwin":
            subprocess.Popen(["open", "-a", app])
        else:
            try:
                subprocess.Popen([app])
            except Exception:
                subprocess.Popen(["xdg-open", app])

    def _screenshot(self, folder):
        folder = os.path.expanduser(folder or "~")
        os.makedirs(folder, exist_ok=True)
        fn = os.path.join(folder, f"insafelabs_{datetime.now():%Y%m%d_%H%M%S}.png")
        pyautogui.screenshot(fn)
        print(f"    [screenshot] {fn}")

    def _window(self, op):
        win = sys.platform.startswith("win")
        mac = sys.platform == "darwin"
        if op == "switch":
            pyautogui.hotkey("command", "tab") if mac else pyautogui.hotkey("alt", "tab")
        elif op == "minimize":
            if win:
                pyautogui.hotkey("win", "down")
            elif mac:
                pyautogui.hotkey("command", "m")
            else:
                pyautogui.hotkey("super", "h")
        elif op == "maximize":
            if win:
                pyautogui.hotkey("win", "up")
            elif mac:
                pyautogui.hotkey("ctrl", "command", "f")
            else:
                pyautogui.hotkey("super", "up")
        elif op == "close":
            pyautogui.hotkey("command", "w") if mac else pyautogui.hotkey("ctrl", "w")
        elif op == "show_desktop":
            if win:
                pyautogui.hotkey("win", "d")
            elif mac:
                pyautogui.hotkey("fn", "f11")
            else:
                pyautogui.hotkey("super", "d")

    # -- per-frame update ---------------------------------------------------
    def update(self, lm):
        s = self.cfg["settings"]
        b = self.cfg["bindings"]
        now = time.time()
        label = classify(lm)
        pinch_dist = dist(lm[4], lm[8])
        is_pinch = pinch_dist < float(s.get("pinch_threshold", 0.055))

        if self.paused:
            return "PAUSED · " + label

        # cursor follows index fingertip
        if s.get("move_cursor", True):
            margin = float(s.get("edge_reach", 0.18))
            smooth = float(s.get("smoothing", 0.35))
            nx = remap_reach(lm[8][0], margin)
            ny = remap_reach(lm[8][1], margin)
            tx, ty = nx * self.screen_w, ny * self.screen_h
            self.cur_x += (tx - self.cur_x) * smooth
            self.cur_y += (ty - self.cur_y) * smooth
            try:
                pyautogui.moveTo(int(self.cur_x), int(self.cur_y), _pause=False)
            except Exception:
                pass

        # pinch -> click / drag
        if is_pinch and not self.pinch_down:
            self.pinch_down = True
            self.pinch_start = now
            drag_bound = b.get("pinch_hold", {}).get("action") == "drag"
            if drag_bound:
                pyautogui.mouseDown()
            else:
                self.run_action(b.get("pinch", {"action": "click"}))
        elif is_pinch and self.pinch_down:
            if not self.dragging and (now - self.pinch_start) > 0.25 and b.get("pinch_hold", {}).get("action") == "drag":
                self.dragging = True
        elif not is_pinch and self.pinch_down:
            self.pinch_down = False
            if self.dragging:
                pyautogui.mouseUp()
            self.dragging = False
            return "pinch"

        if self.pinch_down:
            return "pinch" + (" (drag)" if self.dragging else "")

        # thumb up/down -> scroll (continuous)
        if label in ("thumb_up", "thumb_down") and b.get(label, {}).get("action") == "scroll":
            self.scroll_accel = min(self.scroll_accel + 1, 40)
            base = int(b[label].get("amount", 1))
            amt = int(base * (1 + self.scroll_accel * 0.6) * float(s.get("scroll_speed", 1.0)))
            pyautogui.scroll(amt)
            return label
        else:
            self.scroll_accel = 0

        # discrete gesture -> bound action (hold or instant)
        binding = b.get(label)
        if binding and binding.get("action") not in (None, "none"):
            hold = binding.get("hold", True)
            if not hold:
                if self.hold_label != label:
                    self.hold_label = label
                    self.run_action(binding)
            else:
                if self.hold_label != label:
                    self.hold_label = label
                    self.hold_start = now
                elif now - self.hold_start >= float(s.get("hold_seconds", 1.0)) and now > self.cooldown_until:
                    self.cooldown_until = now + float(s.get("cooldown_seconds", 1.5))
                    self.hold_label = None
                    self.run_action(binding)
        else:
            self.hold_label = None
        return label

    def release(self):
        if self.pinch_down:
            self.pinch_down = False
            self.dragging = False
            try:
                pyautogui.mouseUp()
            except Exception:
                pass
        self.scroll_accel = 0
        self.hold_label = None


def main():
    ap = argparse.ArgumentParser(description="InsafeLabs native PC gesture control (PRO)")
    ap.add_argument("--config", help="path to a gestures JSON config")
    ap.add_argument("--camera", type=int, help="override webcam index")
    ap.add_argument("--edge-reach", type=float, help="override active-region margin 0..0.35")
    ap.add_argument("--smoothing", type=float, help="override cursor smoothing 0.1..0.9")
    ap.add_argument("--no-mirror", action="store_true", help="do NOT mirror the camera")
    ap.add_argument("--print-config", action="store_true", help="print the effective config and exit")
    ap.add_argument("--gestures", action="store_true", help="list supported gestures/actions and exit")
    args = ap.parse_args()

    if args.gestures:
        print("Gestures:", ", ".join(DEFAULT_CONFIG["bindings"].keys()), ", point, other")
        print("Actions: click, double_click, drag, scroll, hotkey, press, type, media, launch, screenshot, window, pause_toggle, none")
        return

    path = cfg_path(args.config)
    cfg = load_config(path)
    if args.camera is not None:
        cfg["settings"]["camera"] = args.camera
    if args.edge_reach is not None:
        cfg["settings"]["edge_reach"] = args.edge_reach
    if args.smoothing is not None:
        cfg["settings"]["smoothing"] = args.smoothing
    if args.no_mirror:
        cfg["settings"]["mirror"] = False

    if args.print_config:
        print(json.dumps(cfg, indent=2))
        return

    pyautogui.FAILSAFE = True
    pyautogui.PAUSE = 0.0

    cam = int(cfg["settings"].get("camera", 0))
    cap = cv2.VideoCapture(cam)
    cap.set(cv2.CAP_PROP_FRAME_WIDTH, 640)
    cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 480)
    if not cap.isOpened():
        print(f"[!] Could not open camera {cam}. Try --camera 1")
        sys.exit(1)

    mp_hands = mp.solutions.hands
    mp_draw = mp.solutions.drawing_utils
    hands = mp_hands.Hands(model_complexity=0, max_num_hands=int(cfg["settings"].get("max_hands", 1)),
                           min_detection_confidence=0.6, min_tracking_confidence=0.5)

    ctrl = Controller(cfg)
    show_help = True
    print("\n[+] InsafeLabs PC control (PRO) is LIVE.  keys: q=quit p=pause r=reload h=help")
    print(f"    Screen {ctrl.screen_w}x{ctrl.screen_h} | config {path}")
    print("    Abort anytime: slam the mouse to the TOP-LEFT corner.\n")

    try:
        while True:
            ok, frame = cap.read()
            if not ok:
                continue
            if cfg["settings"].get("mirror", True):
                frame = cv2.flip(frame, 1)
            h, w = frame.shape[:2]
            res = hands.process(cv2.cvtColor(frame, cv2.COLOR_BGR2RGB))

            label = "no hand"
            if res.multi_hand_landmarks:
                hlm = res.multi_hand_landmarks[0]
                mp_draw.draw_landmarks(frame, hlm, mp_hands.HAND_CONNECTIONS)
                lm = [(p.x, p.y) for p in hlm.landmark]
                label = ctrl.update(lm)
            else:
                ctrl.release()

            # HUD
            m = float(cfg["settings"].get("edge_reach", 0.18))
            cv2.rectangle(frame, (int(m * w), int(m * h)), (int((1 - m) * w), int((1 - m) * h)), (0, 200, 255), 1)
            status = "PAUSED" if ctrl.paused else "LIVE"
            col = (0, 165, 255) if ctrl.paused else (0, 220, 120)
            cv2.putText(frame, f"{status}  {label}", (10, 30), cv2.FONT_HERSHEY_SIMPLEX, 0.7, col, 2)
            cv2.putText(frame, f"last: {ctrl.last_action}", (10, 56), cv2.FONT_HERSHEY_SIMPLEX, 0.5, (200, 200, 200), 1)
            if show_help:
                cv2.putText(frame, "q quit  p pause  r reload  h help  |  corner=abort",
                            (10, h - 14), cv2.FONT_HERSHEY_SIMPLEX, 0.45, (170, 170, 170), 1)

            cv2.imshow("InsafeLabs PC Control (PRO)", frame)
            k = cv2.waitKey(1) & 0xFF
            if k in (ord("q"), 27):
                break
            elif k == ord("p"):
                ctrl.paused = not ctrl.paused
            elif k == ord("h"):
                show_help = not show_help
            elif k == ord("r"):
                cfg = load_config(path)
                ctrl.cfg = cfg
                print("    [config reloaded]")
    except KeyboardInterrupt:
        pass
    finally:
        ctrl.release()
        cap.release()
        cv2.destroyAllWindows()
        hands.close()
        print("\n[+] Stopped. Cursor control released.\n")


if __name__ == "__main__":
    main()
