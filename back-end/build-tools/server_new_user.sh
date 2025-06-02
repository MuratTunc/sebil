#!/bin/bash

set -euo pipefail

# ------------------------- Load .env -------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${SCRIPT_DIR}/.env"

if [[ -f "$ENV_FILE" ]]; then
  # shellcheck source=/dev/null
  source "$ENV_FILE"
else
  echo "❌ Error: .env file not found at $ENV_FILE"
  exit 1
fi

# ------------------------- Variables -------------------------
SERVER_USER="root"
PRIVATE_KEY_PATH="${HOME}/.ssh/id_rsa"


# ------------------------- Colors ----------------------------
RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[0;33m"
RESET="\033[0m"

log_start()    { echo -e "🔄 ${YELLOW}$1${RESET}"; }
log_success()  { echo -e "✅ ${GREEN}$1${RESET}"; }
log_error()    { echo -e "❌ ${RED}$1${RESET}"; }

# ------------------------- Main Logic -------------------------
setup_new_user() {
  log_start "Connecting to $SERVER_IP to set up user '$NEW_USER'..."

  ssh -i "$PRIVATE_KEY_PATH" "$SERVER_USER@$SERVER_IP" bash << EOF
    set -e

    echo "👤 Checking if user '$NEW_USER' exists..."
    if id "$NEW_USER" &>/dev/null; then
      echo "✔️ User '$NEW_USER' already exists. Skipping creation."
    else
      echo "➕ Creating user '$NEW_USER'..."
      useradd -m -s /bin/bash "$NEW_USER"
      echo "$NEW_USER:$NEW_USER" | chpasswd
      echo "🔑 Password set to '$NEW_USER'. Please change it after first login."
    fi

    echo "📂 Setting up SSH for '$NEW_USER'..."
    SSH_DIR="/home/$NEW_USER/.ssh"
    mkdir -p "\$SSH_DIR"
    chmod 700 "\$SSH_DIR"

    if [[ -f "/root/.ssh/authorized_keys" ]]; then
      cp /root/.ssh/authorized_keys "\$SSH_DIR/"
      chmod 600 "\$SSH_DIR/authorized_keys"
      chown -R "$NEW_USER:$NEW_USER" "\$SSH_DIR"
      echo "✔️ SSH authorized_keys copied from root."
    else
      echo "⚠️ Warning: /root/.ssh/authorized_keys not found."
    fi

    echo "👑 Adding user to sudo group..."
    usermod -aG sudo "$NEW_USER"

    echo "🔧 Configuring passwordless sudo..."
    SUDOERS_LINE="$NEW_USER ALL=(ALL) NOPASSWD: ALL"
    grep -qF "\$SUDOERS_LINE" /etc/sudoers || echo "\$SUDOERS_LINE" >> /etc/sudoers

    echo "🔁 Restarting SSH service..."
    systemctl restart ssh || service ssh restart

    echo "💻 Setting shell to /bin/bash..."
    chsh -s /bin/bash "$NEW_USER"

    echo "✅ User '$NEW_USER' setup completed."
EOF

  if [[ $? -eq 0 ]]; then
    log_success "User '$NEW_USER' setup successfully on $SERVER_IP."
  else
    log_error "User setup failed."
    exit 1
  fi
}

# ------------------------- Run --------------------------------
setup_new_user
