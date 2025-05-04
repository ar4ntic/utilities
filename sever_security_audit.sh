#!/usr/bin/env bash
# vm_security_audit.sh - GUI-based Automated security audit for a public-exposed VM
# Uses Whiptail for GUI dialogs.

# Check if Whiptail is installed and install it if necessary (CLI only)
if ! command -v whiptail &> /dev/null; then
  echo "Whiptail is not installed. Attempting to install it..."
  if command -v apt &> /dev/null; then
    sudo apt update && sudo apt install -y whiptail
  elif command -v yum &> /dev/null; then
    sudo yum install -y newt
  elif command -v dnf &> /dev/null; then
    sudo dnf install -y newt
  else
    echo "Unsupported package manager. Please install Whiptail manually and re-run the script."
    exit 1
  fi

  # Verify installation
  if ! command -v whiptail &> /dev/null; then
    echo "Failed to install Whiptail. Please install it manually and re-run the script."
    exit 1
  fi
fi

# Ensure the script has sudo privileges
if ! sudo -v; then
  echo "This script requires sudo privileges. Please run it with a user that has sudo access."
  exit 1
fi

# Refresh sudo timestamp periodically to prevent timeout
while true; do
  sudo -n true
  sleep 60
  kill -0 "$$" || exit
done 2>/dev/null &

# Function to display messages or prompts
prompt_user() {
  local message="$1"
  local default="$2"
  whiptail --inputbox "$message" 10 60 "$default" 3>&1 1>&2 2>&3
}

# Function to display errors
display_error() {
  local message="$1"
  whiptail --msgbox "ERROR: $message" 10 60
}

# Function to display information
display_info() {
  local message="$1"
  whiptail --msgbox "$message" 10 60
}

# Prompt for target URL/IP
TARGET_RAW=$(prompt_user "Enter the target URL or IP address:" "")
if [[ ! "$TARGET_RAW" =~ ^(([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}|[0-9]{1,3}(\.[0-9]{1,3}){3}|\[[0-9a-fA-F:]+\])$ ]]; then
  display_error "The entered target '$TARGET_RAW' is not a valid hostname or IP address."
  exit 1
fi
TARGET="$TARGET_RAW"

# Function to check and prompt for sudo if needed
ensure_sudo() {
  if ! mkdir -p "$OUTDIR" 2>/dev/null; then
    display_info "Insufficient permissions to create the directory: $OUTDIR. Attempting with sudo..."
    if ! sudo -v; then
      display_error "This script requires sudo privileges. Please run it with a user that has sudo access."
      exit 1
    fi
    sudo mkdir -p "$OUTDIR"
    sudo chown "$USER":"$USER" "$OUTDIR"
  fi
}

# Function to validate and sanitize the output directory
validate_outdir() {
  local dir="$1"
  dir=$(echo "$dir" | sed 's:/*$::') # Remove trailing slashes
  if [ -z "$dir" ] || [ "$dir" = "/" ]; then
    display_error "Invalid directory path: '$dir'. Please provide a valid directory. For example, a valid path in your home directory could be: $HOME/audit_results"
    return 1
  fi
  echo "$dir"
}

# Prompt for custom results directory
while true; do
  CUSTOM_OUTDIR=$(prompt_user "Enter a custom directory to save results (leave blank for default):" "")
  if [ -n "$CUSTOM_OUTDIR" ]; then
    OUTDIR=$(validate_outdir "$CUSTOM_OUTDIR")
    if [ $? -eq 0 ]; then
      break
    fi
  else
    SAFE_TARGET=$(echo "$TARGET" | sed 's/[^a-zA-Z0-9]/_/g')
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    OUTDIR="audit_${SAFE_TARGET}_$TIMESTAMP"
    break
  fi
done

# Ensure permissions for the output directory
ensure_sudo

# Redirect output to log file
if ! mkdir -p "$OUTDIR"; then
  display_error "Failed to create output directory: $OUTDIR"
  exit 1
fi
SUMMARY="$OUTDIR/summary.txt"
LOGFILE="$OUTDIR/audit.log"
exec > >(tee -a "$LOGFILE") 2>&1 || {
  display_error "Failed to redirect output to log file: $LOGFILE"
  exit 1
}

# Display information about the audit
display_info "Starting security audit for $TARGET. Results will be saved in $OUTDIR."

# Default Gobuster wordlist and validation
DEFAULT_WORDLIST="$HOME/SecLists/Discovery/Web-Content/common.txt"
if [ ! -f "$DEFAULT_WORDLIST" ]; then
  display_info "Gobuster wordlist not found. Attempting to clone SecLists repository..."
  if [ -d "$HOME/SecLists" ]; then
    display_info "SecLists directory already exists. Skipping clone."
  else
    if ! sudo git clone https://github.com/danielmiessler/SecLists.git "$HOME/SecLists"; then
      display_error "Failed to clone SecLists repository. Please check your network connection and try again."
      exit 1
    fi
  fi
fi

if [ -f "$DEFAULT_WORDLIST" ]; then
  WORDLIST="$DEFAULT_WORDLIST"
else
  WORDLIST=$(prompt_user "Enter the path to the Gobuster wordlist (e.g., /path/to/wordlist.txt):" "")
  if [ -z "$WORDLIST" ] || [ ! -f "$WORDLIST" ]; then
    display_error "No valid wordlist provided. Exiting."
    exit 1
  fi
fi

# Define tasks and messages
declare -a TASKS=(
  "Starting full TCP port scan..."
  "Service/version scan..."
  "UDP port scan..."
  "Web vulnerabilities scan with Nikto..."
  "SSL/TLS configuration scan..."
  "Security headers check..."
  "Directory brute-force with Gobuster..."
  "DNS enumeration..."
  "Certificate details..."
  "Generating recommendations..."
)

# Function to run scans with a working progress bar
run_tasks() {
  local total=${#TASKS[@]}
  local progress_file=$(mktemp)
  
  # Start the progress bar in the background
  (
    while true; do
      if [ -f "$progress_file" ]; then
        cat "$progress_file"
      fi
      sleep 1
    done
  ) | whiptail --gauge "Starting security audit..." 10 70 0 &
  GAUGE_PID=$!
  
  # Function to update the progress bar
  update_progress() {
    local pct=$1
    local msg=$2
    echo "XXX"
    echo "$pct"
    echo "Task: $msg ($pct%)"
    echo "XXX"
  }
  
  # Run each task
  for i in "${!TASKS[@]}"; do
    local task_message="${TASKS[i]}"
    local progress=$(( (i * 100) / total ))
    
    echo "[$(date)] Starting: $task_message" | tee -a "$LOGFILE"
    update_progress "$progress" "$task_message" > "$progress_file"
    
    case $i in
      0)
        echo "Running full TCP port scan with Nmap..." | tee -a "$LOGFILE"
        if ! sudo nmap -sS -Pn -p- "$TARGET" -oN "$OUTDIR/nmap_full.txt" 2>&1 | tee -a "$LOGFILE"; then
          echo "- Warning: Nmap full TCP port scan had issues." | tee -a "$SUMMARY" "$LOGFILE"
        fi
        OPEN_TCP=$(grep -c "open" "$OUTDIR/nmap_full.txt" || echo "0")
        ;;
      1)
        echo "Running service/version scan with Nmap..." | tee -a "$LOGFILE"
        if ! sudo nmap -sV -sC -p 22,80,443 "$TARGET" -oN "$OUTDIR/nmap_sv.txt" 2>&1 | tee -a "$LOGFILE"; then
          display_error "Nmap service/version scan failed."
        fi
        ;;
      2)
        echo "Running UDP port scan with Nmap..." | tee -a "$LOGFILE"
        if ! sudo nmap -sU -Pn -p- "$TARGET" -oN "$OUTDIR/nmap_udp.txt" 2>&1 | tee -a "$LOGFILE"; then
          display_error "Nmap UDP port scan failed."
        fi
        OPEN_UDP=$(grep -c "open" "$OUTDIR/nmap_udp.txt" || true)
        ;;
      3)
        echo "Running web vulnerabilities scan with Nikto..." | tee -a "$LOGFILE"
        if ! nikto -h "https://$TARGET" -o "$OUTDIR/nikto.txt" 2>&1 | tee -a "$LOGFILE"; then
          display_error "Nikto web vulnerabilities scan failed."
        fi
        ;;
      4)
        echo "Running SSL/TLS configuration scan with SSLScan..." | tee -a "$LOGFILE"
        if ! sslscan "$TARGET" > "$OUTDIR/sslscan.txt" 2>&1; then
          echo "- SSL scan failed. Check your target or network connectivity." | tee -a "$SUMMARY" "$LOGFILE"
        else
          if grep -q "SSLv3" "$OUTDIR/sslscan.txt"; then
            echo "- WARNING: SSLv3 is supported. Disable it to prevent vulnerabilities like POODLE." | tee -a "$SUMMARY" "$LOGFILE"
          fi
        fi
        ;;
      5)
        echo "Checking security headers with curl..." | tee -a "$LOGFILE"
        if ! curl -s -D "$OUTDIR/headers.txt" -o /dev/null "https://$TARGET" 2>&1 | tee -a "$LOGFILE"; then
          display_error "Curl request for security headers failed."
        fi
        for hdr in Strict-Transport-Security Content-Security-Policy X-Frame-Options X-Content-Type-Options; do
          if ! grep -q "$hdr" "$OUTDIR/headers.txt"; then
            echo "- Missing header: $hdr" | tee -a "$SUMMARY" "$LOGFILE"
          fi
        done
        ;;
      6)
        echo "Running directory brute-force with Gobuster..." | tee -a "$LOGFILE"
        if ! gobuster dir -u "https://$TARGET" -w "$WORDLIST" -o "$OUTDIR/gobuster.txt" 2>&1 | tee -a "$LOGFILE"; then
          display_error "Gobuster directory brute-force scan failed."
        fi
        ;;
      7)
        echo "Running DNS enumeration with dig..." | tee -a "$LOGFILE"
        if ! dig +noall +answer "$TARGET" > "$OUTDIR/dns_a.txt" 2>&1 | tee -a "$LOGFILE"; then
          display_error "DNS enumeration failed."
        fi
        dig CAA +noall +answer "$TARGET" >> "$OUTDIR/dns_a.txt" 2>&1 | tee -a "$LOGFILE"
        dig TXT +noall +answer "$TARGET" >> "$OUTDIR/dns_a.txt" 2>&1 | tee -a "$LOGFILE"
        dig +short TXT "$TARGET" | grep -q "v=spf1" && echo "- SPF record found." | tee -a "$SUMMARY" "$LOGFILE" || echo "- No SPF record found." | tee -a "$SUMMARY" "$LOGFILE"
        ;;
      8)
        echo "Extracting certificate details with OpenSSL..." | tee -a "$LOGFILE"
        if ! echo | openssl s_client -connect "$TARGET:443" -servername "$TARGET" 2>/dev/null \
          | openssl x509 -noout -dates -issuer -subject > "$OUTDIR/cert.txt" 2>&1 | tee -a "$LOGFILE"; then
          display_error "OpenSSL certificate details extraction failed."
        fi
        ;;
      9)
        echo "Generating recommendations..." | tee -a "$LOGFILE"
        ;;
    esac
    
    echo "[$(date)] Completed: $task_message" | tee -a "$LOGFILE"
  done
  
  # Final progress update
  update_progress "100" "Audit complete" > "$progress_file"
  sleep 2
  
  # Kill the progress bar
  kill $GAUGE_PID 2>/dev/null
  rm "$progress_file" 2>/dev/null
}

# Run the tasks and pipe to whiptail
run_tasks | whiptail --gauge "Security Audit Progress" 10 60 0

# Improved error checking for summary generation
{
  echo "Security Audit Summary for $TARGET"
  echo "Generated: $(date)"
  echo
  echo "Open TCP ports: ${OPEN_TCP:-0}"
  if [ "${OPEN_TCP:-0}" -gt 3 ]; then
    echo "- WARNING: Consider closing unnecessary TCP ports."
  else
    echo "- TCP port count is within expected range."
  fi
  
  if [ -f "$OUTDIR/nmap_full.txt" ]; then
    grep -q "22/tcp.*open" "$OUTDIR/nmap_full.txt" && echo "- SSH (port 22) open: disable root login & enforce key-based auth."
    grep -q "80/tcp.*open" "$OUTDIR/nmap_full.txt" && echo "- HTTP (port 80) open: redirect to HTTPS & enforce HSTS."
    grep -q "443/tcp.*open" "$OUTDIR/nmap_full.txt" && echo "- HTTPS (port 443) open: review weak ciphers in sslscan output."
  else
    echo "- Warning: Nmap scan results not available."
  fi
  
  echo
  if [ -f "$OUTDIR/gobuster.txt" ]; then
    gob_count=$(grep -c "Status: 200" "$OUTDIR/gobuster.txt" || echo "0")
    if [ "$gob_count" -gt 0 ]; then
      echo "- Found $gob_count accessible dirs/files via Gobuster."
    else
      echo "- No common hidden dirs/files found."
    fi
  else
    echo "- Warning: Gobuster results not available."
  fi
  
  if [ -f "$OUTDIR/cert.txt" ]; then
    EXPIRY=$(grep -Po "notAfter=\K.*" "$OUTDIR/cert.txt" || echo "Not available")
    echo "- Certificate expiration date: $EXPIRY"
  else
    echo "- Certificate information not available."
  fi
  
  if [ -f "$OUTDIR/dns_a.txt" ]; then
    grep -q "issue" "$OUTDIR/dns_a.txt" && echo "- CAA record present." || echo "- No CAA record found."
  else
    echo "- DNS information not available."
  fi
} >> "$SUMMARY"

# Display summary
whiptail --textbox "$SUMMARY" 20 70

# Display the full path of the results
RESULTS_DIR_FULL_PATH="$(realpath "$OUTDIR")"
SUMMARY_FILE_FULL_PATH="$(realpath "$SUMMARY")"
display_info "Audit completed. Results saved in:\nDirectory: $RESULTS_DIR_FULL_PATH\nSummary File: $SUMMARY_FILE_FULL_PATH"