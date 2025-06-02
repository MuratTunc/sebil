#!/bin/bash

###############################################################################
# 🛡️ Script Purpose:
# This script configures SSH access for a new user by:
#   🔐 Copying the local private SSH key to the remote server
#   🔧 Setting appropriate permissions
#   🔑 Adding GitHub to known_hosts (to avoid host verification errors)
#
# It uses values from the .env file, including:
#   - SERVER_IP
#   - NEW_USER
#   - PROJECT_NAME
#   - PRIVATE_KEY_PATH
###############################################################################

# Load .env file
LOCAL_ENV_FILE="$(dirname "$0")/.env"
if [ -f "$LOCAL_ENV_FILE" ]; then
  source "$LOCAL_ENV_FILE"
else
  echo "❌ Error: .env file not found at $LOCAL_ENV_FILE"
  exit 1
fi

# Variables
PRIVATE_KEY_PATH="${PRIVATE_KEY_PATH:-$HOME/.ssh/id_rsa}"  # Default if not set
SERVER_REPO_DIR="/home/$NEW_USER/$PROJECT_NAME"

# Color definitions
RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[0;33m"
RESET="\033[0m"

# Logging functions
start()    { echo -e "*********************************************"; echo -e "🔄 ${YELLOW}$1${RESET}"; }
success()  { echo -e "✅ ${GREEN}$1${RESET}"; }
error()    { echo -e "❌ ${RED}$1${RESET}"; }

# ----------------------------------------------------------#

configure_private_ssh_key() {
  start "Copying the private SSH key to the server for user '$NEW_USER'..."
  scp "$PRIVATE_KEY_PATH" "$NEW_USER@$SERVER_IP:/home/$NEW_USER/.ssh/id_rsa"
  if [ $? -eq 0 ]; then
    success "Private SSH key copied successfully!"
  else
    error "Failed to copy the private SSH key to the server."
    exit 1
  fi

  ssh -T "$NEW_USER@$SERVER_IP" << EOF
     chmod 600 /home/$NEW_USER/.ssh/id_rsa
     chown $NEW_USER:$NEW_USER /home/$NEW_USER/.ssh/id_rsa
     ssh-keyscan github.com >> /home/$NEW_USER/.ssh/known_hosts
     chmod 644 /home/$NEW_USER/.ssh/known_hosts
EOF

  if [ $? -eq 0 ]; then
    success "Private SSH key permissions set and GitHub added to known_hosts!"
  else
    error "Failed to configure the private SSH key for the new user."
    exit 1
  fi
}

# ----------------------------------------------------------#
# Run
configure_private_ssh_key
