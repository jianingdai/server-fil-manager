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
if [ ! -e "$BIN" ]; then
  echo "找不到服务程序：$BIN" >&2
  exit 1
fi
BIN_REAL=$(readlink -f "$BIN")
DATA_DIR=${SFM_DATA_DIR:-"$HOME/.local/share/server-file-manager"}
if [ ! -d "$DATA_DIR" ]; then
  echo "服务数据目录不存在：$DATA_DIR" >&2
  exit 1
fi
DATA_DIR=$(CDPATH= cd "$DATA_DIR" && pwd -P)
LISTEN=${SFM_LISTEN:-:8080}
PID_FILE="$DATA_DIR/server-file-manager.pid"

if [ ! -f "$PID_FILE" ]; then
  echo "没有 PID 文件，服务可能已经停止。"
  exit 0
fi
pid=$(cat "$PID_FILE")
case "$pid" in
  ''|*[!0-9]*) echo "PID 文件格式无效：$PID_FILE" >&2; exit 1 ;;
esac
if [ ! -d "/proc/$pid" ]; then
  rm -f "$PID_FILE"
  echo "已清理失效 PID 文件。"
  exit 0
fi

process_matches() {
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
if ! process_matches; then
  echo "PID=$pid 当前不是预期的文件管理服务，为避免误杀未发送信号。" >&2
  exit 1
fi

kill -TERM "$pid"
count=0
while [ "$count" -lt 30 ] && [ -d "/proc/$pid" ]; do
  if ! process_matches "$pid" 2>/dev/null; then
    break
  fi
  sleep 1
  count=$((count + 1))
done
if [ -d "/proc/$pid" ] && process_matches "$pid" 2>/dev/null; then
  echo "服务未在 30 秒内退出；没有强制结束进程，请检查服务日志。" >&2
  exit 1
fi
rm -f "$PID_FILE"
echo "服务已停止。"
