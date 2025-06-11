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

# 3. Update remote IP in all .ovpn files under /etc/openvpn
for cfg in /etc/openvpn/*.ovpn; do
  [[ -f "$cfg" ]] || continue

  echo "Processing $cfg"
  # List and display existing remote lines
  mapfile -t OLD_REMOTES < <(grep -Eo '^remote [0-9.]+' "$cfg" || echo "no remote lines found")
  if (( ${#OLD_REMOTES[@]} )); then
    echo "  Old remote lines:"
    for line in "${OLD_REMOTES[@]}"; do
      echo "    $line"
    done
  else
    echo "  No remote lines found"
  fi

  # Perform replacement
  sed -i -E "s#^(remote +)[0-9.]+#\1$NEW_IP#g" "$cfg"

  # List and display new remote lines
  mapfile -t NEW_REMOTES < <(grep -Eo '^remote [0-9.]+' "$cfg" || echo "no remote lines after replacement")
  echo "  New remote lines:"
  for line in "${NEW_REMOTES[@]}"; do
    echo "    $line"
  done
  echo
done