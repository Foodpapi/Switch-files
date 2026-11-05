#!/usr/bin/env bash
set -u

SEVENZ="/c/Program Files/7-Zip/7z.exe"
ARCHIVE='C:\Users\Peter Allegro\Downloads\split.rar'
NAME='Final Fantasy Resonance [0100606026F12000][v0][US][Base].nsp'
DST="/d/roms/$NAME"
CHUNK=3020524125
LOG="/c/Users/Peter Allegro/AppData/Local/Temp/opencode/7z_err.log"

echo "== clearing old output =="
rm -rf "$DST"
mkdir -p "$DST"

echo "== source NSP md5 (pass 1: decompress, no disk write) =="
SRC_MD5=$(MSYS2_ARG_CONV_EXCL='*' "$SEVENZ" x -so "$ARCHIVE" "*.nsp" 2>"$LOG" | md5sum | awk '{print $1}')
echo "source md5: $SRC_MD5"

echo "== extract + split (pass 2: stream straight to SD) =="
MSYS2_ARG_CONV_EXCL='*' "$SEVENZ" x -so "$ARCHIVE" "*.nsp" 2>"$LOG" | split -b "$CHUNK" -d -a 2 - "$DST/"
RC=("${PIPESTATUS[@]}")
echo "7z exit=${RC[0]}  split exit=${RC[1]}"

echo "== output =="
ls -la "$DST"

echo "== parts md5 =="
PART_MD5=$(cat "$DST"/* 2>/dev/null | md5sum | awk '{print $1}')
echo "parts  md5: $PART_MD5"

if [ "$SRC_MD5" = "$PART_MD5" ]; then
    echo "RESULT: IDENTICAL"
else
    echo "RESULT: MISMATCH"
fi
