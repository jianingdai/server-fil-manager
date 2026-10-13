#!/bin/sh
set -eu

if [ -z "${HOME:-}" ]; then
  echo "HOME must be set" >&2
  exit 1
fi

BIN=${SFM_BIN:-"$HOME/bin/server-file-manager"}
case "$BIN" in
  /*) ;;
  *) BIN="$(pwd -P)/$BIN" ;;
esac
if [ ! -x "$BIN" ]; then
  echo "可执行文件不存在或不可执行：$BIN" >&2
  exit 1
fi
BIN_REAL=$(readlink -f "$BIN")
DATA_DIR=${SFM_DATA_DIR:-"$HOME/.local/share/server-file-manager"}
mkdir -p "$DATA_DIR"
chmod 700 "$DATA_DIR"
DATA_DIR=$(CDPATH= cd "$DATA_DIR" && pwd -P)
LISTEN=${SFM_LISTEN:-:8080}
PID_FILE="$DATA_DIR/server-file-manager.pid"
LOG_FILE="$DATA_DIR/server-file-manager.log"

process_matches() {
  pid=$1
  [ -r "/proc/$pid/cmdline" ] || return 1
  process_exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null || true)
  [ "$process_exe" = "$BIN_REAL" ] || return 1
  args=$(tr '\000' '\n' < "/proc/$pid/cmdline")
  printf '%s\n' "$args" | grep -Fx -- "serve" >/dev/null || return 1
  printf '%s\n' "$args" | awk -v data="$DATA_DIR" -v listen="$LISTEN" '
    $0 == "--data-dir" { if (getline && $0 == data) has_data=1 }
    $0 == "--listen" { if (getline && $0 == listen) has_listen=1 }
    END { exit !(has_data && has_listen) }
  '
}

if [ -f "$PID_FILE" ]; then
  old_pid=$(cat "$PID_FILE")
  case "$old_pid" in
    ''|*[!0-9]*) echo "PID 文件格式无效：$PID_FILE" >&2; exit 1 ;;
  esac
  if [ -d "/proc/$old_pid" ]; then
    if process_matches "$old_pid"; then
      echo "服务已经运行，PID=$old_pid，日志：$LOG_FILE"
      exit 0
    fi
    echo "PID 文件指向仍在运行的其他进程（PID=$old_pid），为避免误操作已停止启动。" >&2
    exit 1
  fi
  rm -f "$PID_FILE"
fi

umask 077
touch "$LOG_FILE"
nohup "$BIN" serve --listen "$LISTEN" --data-dir "$DATA_DIR" >>"$LOG_FILE" 2>&1 </dev/null &
pid=$!
tmp_pid="$PID_FILE.tmp.$$"
printf '%s\n' "$pid" > "$tmp_pid"
chmod 600 "$tmp_pid"
mv "$tmp_pid" "$PID_FILE"
sleep 1
if process_matches "$pid"; then
  echo "服务已在后台启动，PID=$pid，监听=$LISTEN"
  echo "日志：$LOG_FILE"
  exit 0
fi
rm -f "$PID_FILE"
echo "服务启动后很快退出，请检查日志：$LOG_FILE" >&2
tail -n 30 "$LOG_FILE" >&2 || true
exit 1
