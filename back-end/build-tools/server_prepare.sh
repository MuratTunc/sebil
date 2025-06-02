#!/bin/bash

# Load .env file
LOCAL_ENV_FILE="$(dirname "$0")/.env"  # Path to the .env file (same directory as this script)
if [ -f "$LOCAL_ENV_FILE" ]; then
  source "$LOCAL_ENV_FILE"
else
  echo "Error: .env file not found at $LOCAL_ENV_FILE"
  exit 1
fi

# Variables from .env file
SERVER_IP="${SERVER_IP}"  
NEW_USER="${NEW_USER}"    
DOMAIN_NAME="${DOMAIN_NAME}"  
PROJECT_NAME="${PROJECT_NAME}"
REPO_GIT_SSH_LINK="${REPO_GIT_SSH_LINK}"
# ----------------------------------------------------------#


SERVER_USER="root"                    # Assuming root user
PRIVATE_KEY_PATH="$HOME/.ssh/id_rsa"  # Path to private SSH key on local machine
SERVER_REPO_DIR="/home/$NEW_USER/$PROJECT_NAME"  # Dynamically set the repository directory based on NEW_USER
SERVER_BULID_TOOLS_DIR="/home/$NEW_USER/$PROJECT_NAME/back-end/build-tools"  # Directory for the install script
LOCAL_ENV_FILE="$(dirname "$0")/.env"  # Path to the .env file (same directory as this script)
# ----------------------------------------------------------#


# Color definitions
RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[0;33m"
RESET="\033[0m"
# ----------------------------------------------------------#

start() {
  echo -e "*********************************************"
  echo -e "🔄🔄🔄 ${YELLOW}$1${RESET}"
}

success() {
  echo -e "✅✅✅ ${GREEN}$1${RESET}"
}

error() {
  echo -e "❌❌❌ ${RED}$1${RESET}"
}
# ----------------------------------------------------------#




# Function to clone the repository on the server
clone_repository() {
  start "Cloning the GitHub repository on the server droplet..."
  ssh "$NEW_USER@$SERVER_IP" << EOF
    set -e
    ssh-keyscan github.com >> ~/.ssh/known_hosts

    # Check if the directory exists
    echo "Checking if repository directory exists..."
    if [ -d "$SERVER_REPO_DIR" ]; then
      echo "Repository directory exists. Deleting old repository and cloning again..."
      sudo rm -rf "$SERVER_REPO_DIR"  # Delete the entire repository directory
    fi

    # Create the directory again and clone the repository
    echo "Creating the directory and cloning the repository..."
    mkdir -p "$SERVER_REPO_DIR"
    cd "$SERVER_REPO_DIR"

    echo "Cloning the repository..."
    git clone "$REPO_GIT_SSH_LINK" .

    # Change ownership to the appropriate user after cloning
    sudo chown -R mutu:mutu "$SERVER_REPO_DIR"
EOF

  if [ $? -eq 0 ]; then
    success "Repository cloned or updated successfully on the server."
  else
    error "Failed to clone or update the repository on the server."
    exit 1
  fi
}
# ----------------------------------------------------------#


# Function to copy .env file to the server
transfer_envfile() {
  start "Copying the .env file to the server..."
  scp "$LOCAL_ENV_FILE" "$NEW_USER@$SERVER_IP:$SERVER_BULID_TOOLS_DIR/.env"
  if [ $? -eq 0 ]; then
    success ".env file copied successfully to $SERVER_BULID_TOOLS_DIR."
  else
    error "Failed to copy the .env file to the server."
    exit 1
  fi
}


# Function to run the server installation script
install_systemPackages() {
  start "Running server_droplet_installs.sh..."
  ssh "$NEW_USER@$SERVER_IP" << EOF
    set -e
    cd "$SERVER_BULID_TOOLS_DIR"
    sudo ./server_droplet_installs.sh
EOF

  if [ $? -eq 0 ]; then
    success "Server installation script executed successfully!"
  else
    error "Failed to execute the server installation script."
    exit 1
  fi
}
# ----------------------------------------------------------#




# Main Execution
#-------------------------------------#
success "Starting server droplet setup process..."
#-------------------------------------#


#-------------------------------------#
clone_repository
#-------------------------------------#


#-------------------------------------#
transfer_envfile
#-------------------------------------#


success "All tasks completed successfully!"
echo "✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅✅"