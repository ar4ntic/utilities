#!/usr/bin/env bash
# vm_security_audit.sh - GUI-based Automated security audit for a public-exposed VM
# Uses Whiptail for GUI dialogs.

# Required dependencies
DEPENDENCIES=("nmap" "nikto" "sslscan" "gobuster" "curl" "dig" "openssl" "git")

# Function to check and install dependencies
check_dependencies() {
  local missing_deps=()
  
  for dep in "${DEPENDENCIES[@]}"; do
    if ! command -v "$dep" &> /dev/null; then
      missing_deps+=("$dep")
    fi
  done
  
  if [ ${#missing_deps[@]} -eq 0 ]; then
    return 0
  fi
  
  whiptail --yesno "The following dependencies are missing and required for this script:\n$(printf '  - %s\n' "${missing_deps[@]}")\n\nWould you like to install them now?" 20 70
  
  if [ $? -eq 0 ]; then
    echo "Attempting to install missing dependencies..."
    
    if command -v apt &> /dev/null; then
      sudo apt update && sudo apt install -y "${missing_deps[@]}"
    elif command -v yum &> /dev/null; then
      sudo yum install -y "${missing_deps[@]}"
    elif command -v dnf &> /dev/null; then
      sudo dnf install -y "${missing_deps[@]}"
    else
      display_error "Unsupported package manager. Please install the missing dependencies manually and re-run the script."
      echo "Missing dependencies: ${missing_deps[*]}"
      return 1
    fi
    
    # Verify installations
    local still_missing=()
    for dep in "${missing_deps[@]}"; do
      if ! command -v "$dep" &> /dev/null; then
        still_missing+=("$dep")
      fi
    done
    
    if [ ${#still_missing[@]} -gt 0 ]; then
      display_error "Failed to install all required dependencies. Please install them manually and re-run the script."
      echo "Still missing: ${still_missing[*]}"
      return 1
    fi
    
    display_info "All required dependencies have been successfully installed."
    return 0
  else
    display_error "This script requires all dependencies to run properly. Exiting..."
    return 1
  fi
}

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

# Check for required dependencies
check_dependencies || exit 1

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

# Function to run a command with timeout
run_with_timeout() {
  local cmd="$1"
  local timeout_sec="${2:-300}"  # Default 5 minutes timeout
  local log_file="$3"
  local msg="$4"
  
  echo "$msg" | tee -a "$log_file"
  
  # Run the command with timeout
  timeout "$timeout_sec" bash -c "$cmd" 2>&1 | tee -a "$log_file"
  
  local exit_code=${PIPESTATUS[0]}
  if [ $exit_code -eq 124 ]; then
    echo "Command timed out after $timeout_sec seconds: $cmd" | tee -a "$log_file"
    return 124
  elif [ $exit_code -ne 0 ]; then
    echo "Command failed with exit code $exit_code: $cmd" | tee -a "$log_file"
    return $exit_code
  fi
  return 0
}

# Function to run scans with properly working progress bar
run_tasks() {
  local total=${#TASKS[@]}
  
  # Initial progress bar setup
  whiptail --title "Security Audit" --gauge "Initializing security audit..." 10 70 0
  
  for i in "${!TASKS[@]}"; do
    local task_message="${TASKS[i]}"
    local progress=$(( (i * 100) / total ))
    
    # Update the progress bar with current task information
    {
      echo $progress
      echo "XXX"
      echo "Task $((i+1))/$total: ${TASKS[i]}"
      echo "XXX"
    } | whiptail --gauge "Running Security Audit..." 10 70 0
    
    echo "[$(date)] Starting: $task_message" | tee -a "$LOGFILE"
    
    # Check if required tool is available before running a task
    case $i in
      0|1|2)
        if ! command -v nmap &> /dev/null; then
          echo "ERROR: nmap not installed. Skipping task." | tee -a "$LOGFILE"
          continue
        fi
        ;;
      3)
        if ! command -v nikto &> /dev/null; then
          echo "ERROR: nikto not installed. Skipping task." | tee -a "$LOGFILE"
          continue
        fi
        ;;
      4)
        if ! command -v sslscan &> /dev/null; then
          echo "ERROR: sslscan not installed. Skipping task." | tee -a "$LOGFILE"
          continue
        fi
        ;;
      6)
        if ! command -v gobuster &> /dev/null; then
          echo "ERROR: gobuster not installed. Skipping task." | tee -a "$LOGFILE"
          continue
        fi
        ;;
    esac
    
    # Rest of the case statement with timeouts
    case $i in
      0)
        run_with_timeout "sudo nmap -sS -Pn -p- '$TARGET' -oN '$OUTDIR/nmap_full.txt'" 600 "$LOGFILE" "Running full TCP port scan with Nmap..."
        OPEN_TCP=$(grep -c "open" "$OUTDIR/nmap_full.txt" 2>/dev/null || echo "0")
        ;;
      1)
        run_with_timeout "sudo nmap -sV -sC -p 22,80,443 '$TARGET' -oN '$OUTDIR/nmap_sv.txt'" 300 "$LOGFILE" "Running service/version scan with Nmap..."
        ;;
      2)
        run_with_timeout "sudo nmap -sU -Pn --top-ports 100 '$TARGET' -oN '$OUTDIR/nmap_udp.txt'" 300 "$LOGFILE" "Running UDP port scan with Nmap..."
        OPEN_UDP=$(grep -c "open" "$OUTDIR/nmap_udp.txt" 2>/dev/null || echo "0")
        ;;
      3)
        run_with_timeout "nikto -h 'https://$TARGET' -o '$OUTDIR/nikto.txt'" 600 "$LOGFILE" "Running web vulnerabilities scan with Nikto..."
        ;;
      4)
        run_with_timeout "sslscan '$TARGET' > '$OUTDIR/sslscan.txt'" 300 "$LOGFILE" "Running SSL/TLS configuration scan with SSLScan..."
        if grep -q "SSLv3" "$OUTDIR/sslscan.txt" 2>/dev/null; then
          echo "- WARNING: SSLv3 is supported. Disable it to prevent vulnerabilities like POODLE." | tee -a "$SUMMARY" "$LOGFILE"
        fi
        ;;
      5)
        run_with_timeout "curl -s -m 30 -D '$OUTDIR/headers.txt' -o /dev/null 'https://$TARGET'" 60 "$LOGFILE" "Checking security headers with curl..."
        # If https fails, try http
        if [ ! -s "$OUTDIR/headers.txt" ]; then
          run_with_timeout "curl -s -m 30 -D '$OUTDIR/headers.txt' -o /dev/null 'http://$TARGET'" 60 "$LOGFILE" "HTTPS failed, trying HTTP instead..."
        fi
        
        for hdr in Strict-Transport-Security Content-Security-Policy X-Frame-Options X-Content-Type-Options; do
          if ! grep -q "$hdr" "$OUTDIR/headers.txt" 2>/dev/null; then
            echo "- Missing header: $hdr" | tee -a "$SUMMARY" "$LOGFILE"
          fi
        done
        ;;
      6)
        run_with_timeout "gobuster dir -u 'https://$TARGET' -w '$WORDLIST' -o '$OUTDIR/gobuster.txt'" 600 "$LOGFILE" "Running directory brute-force with Gobuster..."
        # If https fails, try http
        if [ ! -s "$OUTDIR/gobuster.txt" ]; then
          run_with_timeout "gobuster dir -u 'http://$TARGET' -w '$WORDLIST' -o '$OUTDIR/gobuster.txt'" 600 "$LOGFILE" "HTTPS failed, trying HTTP for Gobuster..."
        fi
        ;;
      7)
        run_with_timeout "dig +noall +answer '$TARGET' > '$OUTDIR/dns_a.txt' 2>&1" 60 "$LOGFILE" "Running DNS enumeration with dig..."
        run_with_timeout "dig CAA +noall +answer '$TARGET' >> '$OUTDIR/dns_a.txt' 2>&1" 60 "$LOGFILE" "Running CAA DNS lookup..."
        run_with_timeout "dig TXT +noall +answer '$TARGET' >> '$OUTDIR/dns_a.txt' 2>&1" 60 "$LOGFILE" "Running TXT DNS lookup..."
        if dig +short TXT "$TARGET" 2>/dev/null | grep -q "v=spf1"; then
          echo "- SPF record found." | tee -a "$SUMMARY" "$LOGFILE" 
        else
          echo "- No SPF record found." | tee -a "$SUMMARY" "$LOGFILE"
        fi
        ;;
      8)
        run_with_timeout "echo | openssl s_client -connect '$TARGET:443' -servername '$TARGET' 2>/dev/null | openssl x509 -noout -dates -issuer -subject > '$OUTDIR/cert.txt'" 60 "$LOGFILE" "Extracting certificate details with OpenSSL..."
        # Try alternative port 8443 if 443 fails
        if [ ! -s "$OUTDIR/cert.txt" ]; then
          run_with_timeout "echo | openssl s_client -connect '$TARGET:8443' -servername '$TARGET' 2>/dev/null | openssl x509 -noout -dates -issuer -subject > '$OUTDIR/cert.txt'" 60 "$LOGFILE" "Trying alternative port 8443 for certificate..."
        fi
        ;;
      9)
        echo "Generating recommendations..." | tee -a "$LOGFILE"
        ;;
    esac
    
    # Force progress bar update
    {
      echo $((progress + 5))
      echo "XXX"
      echo "Completed: ${TASKS[i]}"
      echo "XXX"
    } | whiptail --gauge "Running Security Audit..." 10 70 0
    sleep 1
    
    echo "[$(date)] Completed: $task_message" | tee -a "$LOGFILE"
  done
  
  # Show completion in progress bar with a delay to ensure visibility
  {
    echo 100
    echo "XXX"
    echo "Audit complete!"
    echo "XXX"
  } | whiptail --gauge "Running Security Audit..." 10 70 0
  sleep 3
}

# Improved summary generation with better error handling
generate_summary() {
  {
    echo "Security Audit Summary for $TARGET"
    echo "Generated: $(date)"
    echo
    echo "TOOLS AVAILABILITY:"
    command -v nmap &> /dev/null && echo "- Nmap: Available" || echo "- Nmap: NOT AVAILABLE (port scanning incomplete)"
    command -v nikto &> /dev/null && echo "- Nikto: Available" || echo "- Nikto: NOT AVAILABLE (web vulnerability scanning incomplete)"
    command -v sslscan &> /dev/null && echo "- SSLScan: Available" || echo "- SSLScan: NOT AVAILABLE (TLS security testing incomplete)"
    command -v gobuster &> /dev/null && echo "- Gobuster: Available" || echo "- Gobuster: NOT AVAILABLE (directory discovery incomplete)"
    echo
    
    echo "SCAN RESULTS:"
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
}

# Replace the direct summary generation with the function call
run_tasks
generate_summary

# Display summary
whiptail --textbox "$SUMMARY" 20 70

# Display the full path of the results
RESULTS_DIR_FULL_PATH="$(realpath "$OUTDIR")"
SUMMARY_FILE_FULL_PATH="$(realpath "$SUMMARY")"
display_info "Audit completed. Results saved in:\nDirectory: $RESULTS_DIR_FULL_PATH\nSummary File: $SUMMARY_FILE_FULL_PATH"