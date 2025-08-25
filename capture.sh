#!/bin/bash

CAPTURE_DIR=""
CAPTURE_USER=""
CAPTURE_GROUP=""
INTERFACE=""
FILE_PREFIX=""
MAX_FILE_SIZE_MB=5
MAX_FILES=2

if [ ! -d "$CAPTURE_DIR" ]; then
  sudo mkdir -p "$CAPTURE_DIR"
fi

sudo chown "$CAPTURE_USER":"$CAPTURE_GROUP" "$CAPTURE_DIR"
sudo chmod 755 "$CAPTURE_DIR"

cleanup() {
  if [ -n "$TCPDUMP_PID" ]; then
    sudo kill -SIGINT "$TCPDUMP_PID"
    wait "$TCPDUMP_PID"
  fi
  echo "tcpdump stopped. Exiting."
  exit 0
}

trap cleanup SIGINT SIGTERM

sudo tcpdump -i "$INTERFACE" -w "$CAPTURE_DIR/$FILE_PREFIX" -C "$MAX_FILE_SIZE_MB" -W "$MAX_FILES" -Z "$CAPTURE_USER" -v &
TCPDUMP_PID=$!

echo "tcpdump started on interface $INTERFACE with PID $TCPDUMP_PID"
