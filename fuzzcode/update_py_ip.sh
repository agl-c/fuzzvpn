#!/usr/bin/env bash
set -euo pipefail

# 1. Get the new IP: use first argument or prompt the user interactively
if [[ "${1:-}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  NEW_IP="$1"
else
  read -rp "Enter the new IP to replace (format x.x.x.x): " NEW_IP
  if [[ ! "$NEW_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "Invalid format; please enter a valid IPv4 address." >&2
    exit 1
  fi
fi

echo "Replacing all old IPs with: $NEW_IP"
echo

# 2. Update client_ip and server_ip in all .py files under /fuzzcode
for f in ./*.py; do
  [[ -f "$f" ]] || continue

  echo "Processing $f"
  # Extract and display the old values
  OLD_CLIENT=$(grep -Eo 'client_ip *= *"[0-9.]+"' "$f" || echo "client_ip not found")
  OLD_SERVER=$(grep -Eo 'server_ip *= *"[0-9.]+"' "$f" || echo "server_ip not found")
  echo "  Old client_ip: ${OLD_CLIENT#*= }"
  echo "  Old server_ip: ${OLD_SERVER#*= }"

  # Perform replacement
  sed -i -E \
    -e "s#(client_ip *= *\")[0-9.]+(\")#\1$NEW_IP\2#g" \
    -e "s#(server_ip *= *\")[0-9.]+(\")#\1$NEW_IP\2#g" \
    "$f"

  # Verify and display the new values
  NEW_CLIENT=$(grep -Eo 'client_ip *= *"[0-9.]+"' "$f" || echo "replacement failed")
  NEW_SERVER=$(grep -Eo 'server_ip *= *"[0-9.]+"' "$f" || echo "replacement failed")
  echo "  New client_ip: ${NEW_CLIENT#*= }"
  echo "  New server_ip: ${NEW_SERVER#*= }"
  echo
done

echo "All replacements in python files complete."