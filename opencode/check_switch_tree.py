#!/usr/bin/env python3
"""Validate the Switch file tree that lives on the SD card (FAT32, D:\\ == repo root).

Why this exists
---------------
Atmosphere's cheat manager (dmnt) and the Tesla overlay host (nx-ovlloader) both fail
*silently* or with a generic fatal when a file is misnamed, truncated or over a hard
internal limit.  Every check below maps to a real failure we have seen on this card:

  * cheat file must be named <BUILDID>.txt or dmnt never opens it
    (atmosphere/contents/<TID>/cheats/<BID>.txt, lowercase-in-source but FAT32 is
    case-insensitive, so case does not matter)
  * dmnt MaxCheatCount = 0x80, entry 0 is the master cheat -> at most 127 [names]
    that carry opcodes; more than that makes ParseCheats() return false, and
    AttachToApplicationProcess(on_process_launch=true) then refuses to attach at all
  * CheatVirtualMachine MaximumProgramOpcodeCount = 0x400 words summed over all
    ENABLED cheats; over that, LoadProgram() returns false and no cheat runs
  * a cheat file >= 64 KB (g_text_file_buffer) is rejected outright
  * any byte that is not whitespace / '[' / ']' / hex makes ParseCheats() return false
  * nx-ovlloader loadNro() reads the whole .ovl into its heap; a 0-byte or truncated
    .ovl (interrupted SD copy) makes it fatalThrow(...,4) -> 2347-0004, which kills
    every overlay, not just the bad one
  * FAT32 caps a single file at 4 GiB - 1

Usage:  python3 opencode/check_switch_tree.py [--root D:\\] [--manifest]
Exit code 0 = no errors (warnings allowed), 1 = at least one error.
"""

import argparse
import hashlib
import os
import re
import struct
import sys

OPCODE8 = re.compile(r"^[0-9A-Fa-f]{8}$")
HEXTOK = re.compile(r"^[0-9A-Fa-f]{1,8}$")

MAX_CHEAT_SLOTS = 0x80 - 1          # dmnt: MaxCheatCount=0x80, slot 0 = master cheat
MAX_OPCODES_PER_CHEAT = 0x100       # CheatDefinition::opcodes[0x100]
MAX_PROGRAM_OPCODES = 0x400         # CheatVirtualMachine::MaximumProgramOpcodeCount
MAX_CHEAT_FILE = 64 * 1024          # dmnt: g_text_file_buffer[64_KB]
FAT32_MAX_FILE = 4 * 1024 ** 3 - 1
OVL_DEFAULT_HEAP = 4 * 1024 * 1024  # nx-ovlloader >= 2.0.3 default (4 MB)

errors = []
warnings = []
notes = []


def err(fmt, *a):
    errors.append(fmt % a)


def warn(fmt, *a):
    warnings.append(fmt % a)


def note(fmt, *a):
    notes.append(fmt % a)


def rel(root, p):
    return os.path.relpath(p, root).replace(os.sep, "/")


# ---------------------------------------------------------------- cheats
def analyse_cheat_text(path):
    """Return (slots_used, opcode_words_total, max_words_one_cheat, problems[]).

    Mirrors ams::dmnt::cheat::CheatProcessManager::ParseCheats(): a [name] line takes
    the first entry whose num_opcodes == 0, so a [name] with no opcodes does NOT cost a
    slot (it is overwritten by the following name).
    """
    problems = []
    raw = open(path, "rb").read()
    if raw[:3] == b"\xef\xbb\xbf":
        problems.append("UTF-8 BOM at offset 0 - ParseCheats() rejects it, file will not load")
    size = len(raw)
    if size >= MAX_CHEAT_FILE:
        problems.append("file is %d bytes >= %d (dmnt g_text_file_buffer) - rejected outright"
                        % (size, MAX_CHEAT_FILE))
    text = raw.decode("utf-8", "replace")
    slots = []          # [name, opcode_words]
    cur = None
    for lineno, line in enumerate(text.split("\n"), 1):
        s = line.strip()
        if not s:
            continue
        if s.startswith("["):
            if not s.endswith("]"):
                problems.append("line %d: '[' without ']'" % lineno)
                continue
            if cur is not None and cur[1] > 0:
                slots.append(cur)
            cur = [s, 0]
            continue
        if s.endswith("]"):
            problems.append("line %d: stray ']'" % lineno)
            continue
        toks = s.split()
        if OPCODE8.match(toks[0]):
            bad = [t for t in toks if not HEXTOK.match(t)]
            if bad:
                problems.append("line %d: non-hex token %r - ParseCheats() aborts" % (lineno, bad[0]))
                continue
            if cur is None:
                problems.append("line %d: opcode before any [name] - ParseCheats() aborts" % lineno)
                continue
            cur[1] += len(toks)
        else:
            problems.append("line %d: %r is not an opcode - ParseCheats() aborts on any "
                            "unexpected character (comments are not supported)" % (lineno, s[:40]))
    if cur is not None and cur[1] > 0:
        slots.append(cur)

    used = len(slots)
    total_words = sum(n for _, n in slots)
    max_one = max((n for _, n in slots), default=0)
    if used > MAX_CHEAT_SLOTS:
        problems.append("%d cheat entries > %d: GetFreeCheatEntry() fails, ParseCheats() "
                        "returns false and dmnt will NOT attach to the game" % (used, MAX_CHEAT_SLOTS))
    if max_one > MAX_OPCODES_PER_CHEAT:
        problems.append("a single cheat has %d opcode words > %d" % (max_one, MAX_OPCODES_PER_CHEAT))
    return used, total_words, max_one, problems


def check_cheats(root):
    contents = os.path.join(root, "atmosphere", "contents")
    if not os.path.isdir(contents):
        warn("no atmosphere/contents directory under %s", root)
        return
    for tid in sorted(os.listdir(contents)):
        cdir = os.path.join(contents, tid, "cheats")
        if not os.path.isdir(cdir):
            continue
        if not re.fullmatch(r"[0-9A-Fa-f]{16}", tid):
            err("atmosphere/contents/%s is not a 16-hex-digit title id - dmnt will not find it", tid)
            continue
        files = sorted(f for f in os.listdir(cdir) if f.lower().endswith(".txt"))
        active = [f for f in files if re.fullmatch(r"[0-9A-Fa-f]{16}\.txt", f)]
        spares = [f for f in files if f not in active]
        print("cheats  %s  (%d txt: %d active, %d spare)" % (rel(root, cdir), len(files),
                                                              len(active), len(spares)))
        if not files:
            continue
        if not active:
            err("%s has no <BUILDID>.txt, so dmnt reads nothing; only inert name(s) present: %s",
                rel(root, cdir), ", ".join(spares) or "(none)")
        for f in files:
            p = os.path.join(cdir, f)
            used, words, max_one, problems = analyse_cheat_text(p)
            tag = "active" if f in active else "spare "
            print("        [%s] %-26s %6d B  %3d entries (<= %d)  %4d opcode words (<= %d if all on)"
                  % (tag, f, os.path.getsize(p), used, MAX_CHEAT_SLOTS, words, MAX_PROGRAM_OPCODES))
            for pr in problems:
                (err if f in active else warn)("%s/%s: %s", rel(root, cdir), f, pr)
            if f in active and words > MAX_PROGRAM_OPCODES:
                warn("%s/%s: enabling every cheat would be %d words > %d, so no cheat runs - "
                     "switch on one group at a time", rel(root, cdir), f, words, MAX_PROGRAM_OPCODES)
        if active and spares:
            note("%s: %s not read by dmnt (name is not <BUILDID>.txt); kept as inert spare(s)",
                 rel(root, cdir), ", ".join(spares))
        tog = os.path.join(cdir, "toggles.txt")
        if os.path.exists(tog):
            sz = os.path.getsize(tog)
            if sz == 0:
                note("%s: empty toggles.txt (fine: no saved toggles)", rel(root, cdir))
            else:
                used, words, max_one, problems = analyse_cheat_text(tog)
                print("        [toggl] toggles.txt %d B" % sz)
                for pr in problems:
                    warn("%s/toggles.txt: %s", rel(root, cdir), pr)


# ---------------------------------------------------------------- overlays
def nro_info(path):
    data = open(path, "rb").read()
    out = {"size": len(data)}
    if len(data) < 0x40 or data[0x10:0x14] != b"NRO0":
        out["error"] = "no NRO0 header at 0x10 (not a NRO/OVL, or truncated)"
        return out
    out["nro_size"] = struct.unpack("<Q", data[0x18:0x20])[0]
    segs = [struct.unpack("<II", data[0x20 + i * 8:0x28 + i * 8]) for i in range(3)]
    out["segs"] = segs
    out["bss"] = struct.unpack("<Q", data[0x38:0x40])[0]
    if out["nro_size"] > out["size"]:
        out["error"] = ("TRUNCATED: NRO header declares %d bytes but the file holds %d - "
                        "ovlloader's fsFileRead/validate path will fatal 2347-0004"
                        % (out["nro_size"], out["size"]))
    for i, (off, sz) in enumerate(segs):
        if off >= out["nro_size"] or sz > out["nro_size"] - off:
            out["error"] = "segment %d (off %#x size %#x) is outside the NRO (%#x) - " \
                           "nx-ovlloader fatalThrow(...,6)" % (i, off, sz, out["nro_size"])
            break
    out["map_total"] = (out["nro_size"] + out["bss"] + 0xFFF) & ~0xFFF
    return out


def check_overlays(root, heap=None):
    if heap is None:
        heap = OVL_DEFAULT_HEAP
        cfg = os.path.join(root, "config", "nx-ovlloader", "heap_size.bin")
        if os.path.exists(cfg) and os.path.getsize(cfg) >= 8:
            heap = struct.unpack("<Q", open(cfg, "rb").read(8))[0]
    live = os.path.join(root, "switch", ".overlays")
    parked = os.path.join(root, "switch", ".overlays_disabled")
    for label, d in (("live", live), ("parked", parked)):
        if not os.path.isdir(d):
            if label == "live":
                msg = ("%s does not exist - nx-ovlloader chainloads switch/.overlays/ovlmenu.ovl at "
                       "boot, so nothing can open an overlay" % rel(root, d))
                (err if os.path.isdir(os.path.join(root, "switch")) else warn)(msg)
            continue
        ovl = sorted(f for f in os.listdir(d) if f.lower().endswith(".ovl"))
        print("overlays %s  %s  (%d .ovl, loader heap %d KB)" % (label, rel(root, d), len(ovl), heap // 1024))
        if not ovl:
            warn("%s is empty - Ultrahand/Tesla menu cannot load (ovlloader exits, 2347-0004 class)", rel(root, d))
        for f in ovl:
            p = os.path.join(d, f)
            info = nro_info(p)
            if "error" in info:
                err("%s/%s: %s", rel(root, d), f, info["error"])
                continue
            fits = info["map_total"] <= heap
            line = ("        %-24s %9d B  nro %#x bss %#x -> needs %d KB"
                    % (f, info["size"], info["nro_size"], info["bss"], info["map_total"] // 1024))
            print(line + ("  ok" if fits else "  TOO BIG"))
            if not fits:
                err("%s/%s needs %d KB but the ovlloader heap is %d KB - write %d to "
                    "config/nx-ovlloader/heap_size.bin (or park the overlay) or ovlloader "
                    "fails to map it (2347-0004 for every overlay)"
                    % (rel(root, d), f, info["map_total"] // 1024, heap // 1024, info["map_total"])
                    )
        menu = os.path.join(d, "ovlmenu.ovl")
        if label == "live" and not os.path.exists(menu):
            err("%s has no ovlmenu.ovl - nx-ovlloader loads it at boot and after every "
                "overlay exits; without it no overlay key opens anything", rel(root, d))


# ---------------------------------------------------------------- configs / misc
def check_config(root):
    p = os.path.join(root, "atmosphere", "config", "system_settings.ini")
    t = os.path.join(root, "atmosphere", "config_templates", "system_settings.ini")
    if not os.path.exists(p):
        err("atmosphere/config/system_settings.ini is missing (Atmosphere falls back to defaults, "
            "i.e. cheats ENABLED by default)")
        return
    txt = open(p, encoding="utf-8", errors="replace").read()
    active = {}
    for line in txt.split("\n"):
        s = line.strip()
        if s and not s.startswith(";") and "=" in s:
            k, v = [x.strip() for x in s.split("=", 1)]
            active[k] = v
    print("config  %s  (%d live setting(s))" % (rel(root, p), len(active)))
    want = ("dmnt_cheats_enabled_by_default", "u8!0x0")
    if active.get(want[0]) != want[1]:
        err("[%s] must be %s so every cheat starts off (got %r)", want[0], want[1],
            active.get(want[0], "absent"))
    for stale in ("enable_htc", "enable_standalone_gdbstub", "enable_log_manager"):
        if stale in active:
            if stale == "enable_log_manager" and active[stale] in ("u8!0x1",):
                note("enable_log_manager = u8!0x1 is on: remember to turn it back off after debugging")
            elif stale != "enable_log_manager":
                err("%s = %s is not in the official template; enable_standalone_gdbstub starts the "
                    "built-in dmnt.gen2 TCP GDB server (port 22225) - remove the line",
                    stale, active[stale])
    if os.path.exists(t):
        tpl = open(t, encoding="utf-8", errors="replace").read()
        tactive = set()
        for line in tpl.split("\n"):
            s2 = line.strip().lstrip(";").strip()
            if s2 and "=" in s2:
                tactive.add(s2.split("=", 1)[0].strip())
        extra = sorted(set(active) - tactive)
        if extra:
            warn("setting(s) not in the %s template at all (typo or leftover from another "
                 "version): %s", os.path.basename(t), ", ".join(extra))
        else:
            note("every live setting in system_settings.ini is a key the shipped template documents")


def check_home_daemon(root):
    d = os.path.join(root, "atmosphere", "contents", "0100000000001000")
    if not os.path.isdir(d):
        note("no atmosphere/contents/0100000000001000 (qlaunch override / HOME daemon)")
        return
    fork = os.path.join(d, "fork.txt")
    loader = os.path.join(d, "breeze_loader", "main")
    ex = os.path.join(d, "exefs.nsp")
    tag = []
    if os.path.exists(ex):
        blob = open(ex, "rb").read()
        tag.append("exefs.nsp %d B" % len(blob))
        tag.append("SwitchU fork" if b"switchu-daemon" in blob else "NOT the SwitchU fork (uLaunch?)")
    print("HOME    %s  (%s)" % (rel(root, d), ", ".join(tag)))
    if not os.path.exists(fork):
        warn("missing fork.txt - Breeze reads atmosphere/contents/0100000000001000/fork.txt "
             "(interface=N, version=N) and reports 'not installed (or upstream SwitchU)' without it; "
             "install switch/Breeze/home_daemon.zip from Breeze's Settings")
    if not os.path.exists(loader):
        warn("missing breeze_loader/main (+ main.npdm) - that is how the HOME daemon starts Breeze "
             "in keep/overlay mode; home_daemon.zip carries it")
    else:
        note("breeze_loader present")


def check_sizes(root):
    bad = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [x for x in dirnames if x not in (".git", "node_modules")]
        for f in filenames:
            p = os.path.join(dirpath, f)
            try:
                sz = os.path.getsize(p)
            except OSError:
                continue
            if sz > FAT32_MAX_FILE:
                bad.append((rel(root, p), sz))
            if sz == 0 and (f.lower().endswith((".ovl", ".nro", ".nsp", ".romfs", ".txt")) or f == "package3"):
                err("zero-length file %s - an interrupted copy to the SD card; this is what makes "
                    "ovlloader/dmnt refuse to load it", p)
    for p, sz in bad:
        err("%s is %d bytes > the FAT32 4 GiB per-file cap - it cannot live on the SD card "
            "(split it, e.g. 3020524125-byte parts)", p, sz)
    if not bad:
        note("no file exceeds the FAT32 4 GiB per-file cap")


# What must be byte-perfect on the card, plus (optionally) where the trusted copy is staged in
# this repo.  cardpath -> staged copy, used when the card itself is not mounted (e.g. running
# this check on the repo instead of D:\).
MANIFEST_TARGETS = [
    "atmosphere/config/system_settings.ini",
    "atmosphere/config_templates/system_settings.ini",
    "atmosphere/package3",
    "atmosphere/stratosphere.romfs",
    "atmosphere/hbl.nsp",
    "atmosphere/reboot_payload.bin",
    "atmosphere/contents/0100606026F12000/cheats/84E182F72EE1DA4F.txt",
    "atmosphere/contents/0100606026F12000/cheats/84E182F72EE1DA4F.v1.txt",
    "atmosphere/contents/010022400BE5A000/cheats/CDC49702EE3DF923.txt",
    "atmosphere/contents/0100000000001000/exefs.nsp",
    "atmosphere/contents/010000000000d609.disabled/exefs.nsp",
    "switch/breeze/Breeze.nro",
    "switch/.overlays/ovlmenu.ovl",
    "switch/.overlays/breezehand.ovl",
    "switch/.overlays/breezehand_light.ovl",
    "switch/.overlays/breezehand_watch.ovl",
    "switch/.overlays/bookmark.ovl",
    "switch/.overlays/editcheat.ovl",
    "switch/.overlays/editcheatk.ovl",
]
STAGED_ALIAS = {
    "switch/breeze/Breeze.nro": "opencode/breeze_stage/switch/breeze/Breeze.nro",
}
for _o in ("breezehand.ovl", "breezehand_light.ovl", "breezehand_watch.ovl",
           "bookmark.ovl", "editcheat.ovl", "editcheatk.ovl"):
    STAGED_ALIAS["switch/.overlays/" + _o] = "opencode/breezehand_x/switch/.overlays/" + _o


def digest(path):
    h = hashlib.md5()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def write_manifest(root):
    lines = ["# md5  size  cardpath  [stagedpath]",
             "# cardpath is relative to the SD card root (D:\\), which this repo mirrors.",
             "# regenerate: python3 opencode/check_switch_tree.py --gen-manifest"]
    for path in MANIFEST_TARGETS:
        p = os.path.join(root, path.replace("/", os.sep))
        alias = STAGED_ALIAS.get(path)
        if not os.path.exists(p) and alias:
            p = os.path.join(root, alias.replace("/", os.sep))
        if not os.path.exists(p):
            continue
        extra = "  " + alias if (alias and p != os.path.join(root, path.replace("/", os.sep))) else ""
        lines.append("%s %d %s%s" % (digest(p), os.path.getsize(p), path, extra))
    out = os.path.join(root, "opencode", "manifest.md5")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    open(out, "w", encoding="utf-8", newline="\n").write("\n".join(lines) + "\n")
    print("wrote %s (%d entries)" % (rel(root, out), len(lines) - 3))


def check_manifest(root):
    m = os.path.join(root, "opencode", "manifest.md5")
    if not os.path.exists(m):
        err("%s not found", rel(root, m))
        return
    ok = miss = bad = staged = 0
    for line in open(m, encoding="utf-8"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 3:
            continue
        md5, size, path = parts[0], int(parts[1]), parts[2]
        alias = parts[3] if len(parts) > 3 else None
        p = os.path.join(root, path.replace("/", os.sep))
        if not os.path.exists(p) and alias:
            p, staged = os.path.join(root, alias.replace("/", os.sep)), staged + 1
        if not os.path.exists(p):
            err("manifest: %s is missing from the card", path)
            miss += 1
            continue
        if os.path.getsize(p) != size:
            err("manifest: %s is %d bytes, expected %d (truncated copy?)", path, os.path.getsize(p), size)
            bad += 1
            continue
        if digest(p) != md5:
            err("manifest: %s md5 %s != expected %s", path, digest(p), md5)
            bad += 1
        else:
            ok += 1
    print("manifest %s  (%d ok, %d wrong, %d missing%s)"
          % (rel(root, m), ok, bad, miss, (", %d via staged copy" % staged) if staged else ""))
        if os.path.getsize(p) != size:
            err("manifest: %s is %d bytes, expected %d (truncated copy?)", path, os.path.getsize(p), size)
            bad += 1
            continue
        h = hashlib.md5()
        with open(p, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        if h.hexdigest() != md5:
            err("manifest: %s md5 %s != expected %s", path, h.hexdigest(), md5)
            bad += 1
        else:
            ok += 1
    print("manifest %s  (%d ok, %d wrong, %d missing)" % (rel(root, m), ok, bad, miss))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=".", help="SD card root (D:\\) or the repo that mirrors it")
    ap.add_argument("--manifest", action="store_true", help="also verify opencode/manifest.md5")
    ap.add_argument("--gen-manifest", action="store_true", help="write opencode/manifest.md5")
    a = ap.parse_args()
    root = os.path.abspath(a.root)

    if a.gen_manifest:
        write_manifest(root)
        return 0

    print("=== Switch tree check: %s ===" % root)
    check_cheats(root)
    check_overlays(root)
    check_config(root)
    check_home_daemon(root)
    check_sizes(root)
    if a.manifest:
        check_manifest(root)

    print()
    for m in errors:
        print("ERROR   %s" % m)
    for m in warnings:
        print("WARN    %s" % m)
    for m in notes:
        print("note    %s" % m)
    print("\n%d error(s), %d warning(s)" % (len(errors), len(warnings)))
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
