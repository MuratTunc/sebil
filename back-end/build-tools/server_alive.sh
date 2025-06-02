#!/bin/bash

###############################################################################
# 🧠 Script Purpose:
# This script checks the availability of a remote server before deployment.
#
# It performs the following checks:
#   📡 1. ICMP Ping Test – to see if the server responds (non-blocking)
#   🔌 2. TCP Port 22 Test – to verify SSH is reachable
#   🔁 3. SSH Connection Attempt – retries SSH login N times before failing
#
# Useful before running remote deployment or setup scripts like setup_new_user.sh.
###############################################################################

# Configuration
SERVER_USER="root"
SERVER_IP="64.23.138.28"
RETRY_LIMIT=3
DELAY=3  # Seconds between retries

# Colors
RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[0;33m"
RESET="\033[0m"

# Logging functions
log_info()    { echo -e "🔍 ${YELLOW}$1${RESET}"; }
log_success() { echo -e "✅ ${GREEN}$1${RESET}"; }
log_error()   { echo -e "❌ ${RED}$1${RESET}"; }

# Ping check
log_info "Pinging $SERVER_IP..."
ping -c 2 "$SERVER_IP" >/dev/null 2>&1
if [ $? -ne 0 ]; then
  log_error "Ping failed or ICMP blocked. Continuing with TCP check..."
else
  log_success "Ping successful."
fi

# TCP check on port 22
log_info "Checking if TCP port 22 is open on $SERVER_IP..."
if timeout 3 bash -c "</dev/tcp/$SERVER_IP/22" 2>/dev/null; then
  log_success "Port 22 is open!"
else
  log_error "TCP port 22 is not reachable. SSH might fail."
fi

# Retry SSH connection
log_info "Trying SSH connection to $SERVER_USER@$SERVER_IP..."
for ((i=1; i<=RETRY_LIMIT; i++)); do
  ssh -o ConnectTimeout=5 "$SERVER_USER@$SERVER_IP" "echo 'Connected successfully'" 2>/dev/null
  if [ $? -eq 0 ]; then
    log_success "SSH connection successful on attempt $i!"
    exit 0
  else
    log_error "SSH attempt $i failed. Retrying in $DELAY seconds..."
    sleep $DELAY
  fi
done

log_error "All $RETRY_LIMIT SSH attempts failed. Server might be down or unreachable."
exit 1
