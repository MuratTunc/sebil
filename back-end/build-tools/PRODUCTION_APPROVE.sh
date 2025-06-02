#!/bin/bash

# Load .env file
LOCAL_ENV_FILE="$(dirname "$0")/.env"
if [ -f "$LOCAL_ENV_FILE" ]; then
  source "$LOCAL_ENV_FILE"
else
  echo "Error: .env file not found at $LOCAL_ENV_FILE"
  exit 1
fi

# Variables from .env file
SERVER_IP="${SERVER_IP}"  
NEW_USER="${NEW_USER}"  
SERVER_REPO_DIR="/home/$NEW_USER/zeheb"
# ----------------------------------------------------------#

# Colors
GREEN="\033[0;32m"
RED="\033[0;31m"
RESET="\033[0m"
# ----------------------------------------------------------#

# Functions
success() { echo -e "${GREEN}$1${RESET}"; }
error() { echo -e "${RED}$1${RESET}"; exit 1; }
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

transfer_envfile() {
  if [ "$1" = true ]; then
    success "Copying the .env file to the server..."
    scp "$LOCAL_ENV_FILE" "$NEW_USER@$SERVER_IP:$SERVER_REPO_DIR/back-end/build-tools/.env"
    [ $? -eq 0 ] && success "Successfully transferred .env file!" || error "Failed to transfer .env file."
  fi
}



# Function to run build-services.sh scriptfor back-end services
build_services() {
  start "Running build-services.sh scripts to build back-end services..."
  ssh "$NEW_USER@$SERVER_IP" << EOF
    set -e  # Exit immediately if a command fails
    set -x  # Print each command before executing (debug mode)
    cd "$SERVER_BULID_TOOLS_DIR"
    echo "🔥 Building Services..."
    sudo ./build-services.sh build-all
EOF

  if [ $? -eq 0 ]; then
    success "Back-end services built and started successfully!"
  else
    error "Failed to build and start back-end services."
    exit 1
  fi
}
# ----------------------------------------------------------#



# Main Execution
success "******** STARTING PRODUCTION APPROVE PROCESS ********"
clone_repository true
transfer_envfile true
build_services true
success "All tasks completed successfully!"