#!/usr/bin/env bash
# vm_security_audit.sh - GUI-based Automated security audit for a public-exposed VM
# Uses Whiptail for GUI dialogs if available, otherwise falls back to terminal input/output.

# Check if Whiptail is installed
if ! command -v whiptail &> /dev/null; then
  echo "Whiptail is not installed. Please install it and re-run the script."
  exit 1
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

# Check if a graphical environment is available
#if [ -z "$DISPLAY" ]; then
# USE_GUI=false
#  echo "No graphical environment detected. Falling back to terminal mode."
#else
#  USE_GUI=true
#fi

# Function to display messages or prompts
prompt_user() {
  local message="$1"
  local default="$2"
  if $USE_GUI; then
    whiptail --inputbox "$message" 10 60 "$default" 3>&1 1>&2 2>&3
  else
    read -p "$message [$default]: " input
    echo "${input:-$default}"
  fi
}

# Function to display errors
display_error() {
  local message="$1"
  if $USE_GUI; then
    whiptail --msgbox "ERROR: $message" 10 60
  else
    echo "ERROR: $message" >&2
  fi
}

# Function to display information
display_info() {
  local message="$1"
  if $USE_GUI; then
    whiptail --msgbox "$message" 10 60
  else
    echo "$message"
  fi
}

# Prompt for target URL/IP
TARGET_RAW=$(prompt_user "Enter the target URL or IP address:" "")
if [[ ! "$TARGET_RAW" =~ ^(([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}|[0-9]{1,3}(\.[0-9]{1,3}){3}|\[[0-9a-fA-F:]+\])$ ]]; then
  display_error "The entered target '$TARGET_RAW' is not a valid hostname or IP address."
  exit 1
fi
TARGET="$TARGET_RAW"

# Prompt for custom results directory
CUSTOM_OUTDIR=$(prompt_user "Enter a custom directory to save results (leave blank for default):" "")
if [ -n "$CUSTOM_OUTDIR" ]; then
  OUTDIR="$CUSTOM_OUTDIR"
else
  SAFE_TARGET=$(echo "$TARGET" | sed 's/[^a-zA-Z0-9]/_/g')
  TIMESTAMP=$(date +%Y%m%d_%H%M%S)
  OUTDIR="audit_${SAFE_TARGET}_$TIMESTAMP"
  while [ -d "$OUTDIR" ]; do
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    OUTDIR="audit_${SAFE_TARGET}_$TIMESTAMP"
  done
fi

# Check if the user has write permissions for the output directory
if ! mkdir -p "$OUTDIR" 2>/dev/null; then
  display_error "Cannot create or write to the directory: $OUTDIR. Please check permissions."
  exit 1
fi

SUMMARY="$OUTDIR/summary.txt"
LOGFILE="$OUTDIR/audit.log"
exec > >(tee -a "$LOGFILE") 2>&1

# Display information about the audit
display_info "Starting security audit for $TARGET. Results will be saved in $OUTDIR."

# Default Gobuster wordlist and validation
DEFAULT_WORDLIST="$HOME/SecLists/Discovery/Web-Content/common.txt"
if [ ! -f "$DEFAULT_WORDLIST" ]; then
  display_info "Gobuster wordlist not found. Attempting to clone SecLists repository..."
  if [ -d "$HOME/SecLists" ]; then
    display_info "SecLists directory already exists. Skipping clone."
  else
    if ! git clone https://github.com/danielmiessler/SecLists.git "$HOME/SecLists"; then
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

# Function to run scans and update progress
run_tasks() {
  local total=${#TASKS[@]}
  echo "<?xml version=1.0?>"
  echo "<progress>"
  for i in "${!TASKS[@]}"; do
    pct=$(( (i+1)*100/total ))
    echo "<step><pct>$pct</pct><msg>${TASKS[i]}</msg></step>"
    case $i in
      0)
        nmap -sS -Pn -p- "$TARGET" -oN "$OUTDIR/nmap_full.txt";
        OPEN_TCP=$(grep -c "open" "$OUTDIR/nmap_full.txt" || true);
        ;;
      1)
        nmap -sV -sC -p 22,80,443 "$TARGET" -oN "$OUTDIR/nmap_sv.txt";
        ;;
      2)
        nmap -sU -Pn -p- "$TARGET" -oN "$OUTDIR/nmap_udp.txt";
        OPEN_UDP=$(grep -c "open" "$OUTDIR/nmap_udp.txt" || true);
        ;;
      3)
        nikto -h "https://$TARGET" -o "$OUTDIR/nikto.txt";
        ;;
      4)
        if ! sslscan "$TARGET" > "$OUTDIR/sslscan.txt" 2>/dev/null; then
          echo "- SSL scan failed. Check your target or network connectivity." >> "$SUMMARY"
        else
          if grep -q "SSLv3" "$OUTDIR/sslscan.txt"; then
            echo "- WARNING: SSLv3 is supported. Disable it to prevent vulnerabilities like POODLE." >> "$SUMMARY"
          fi
        fi
        ;;
      5)
        curl -s -D "$OUTDIR/headers.txt" -o /dev/null "https://$TARGET";
        for hdr in Strict-Transport-Security Content-Security-Policy X-Frame-Options X-Content-Type-Options; do
          if ! grep -q "$hdr" "$OUTDIR/headers.txt"; then
            echo "- Missing header: $hdr" >> "$SUMMARY"
          fi
        done
        ;;
      6)
        gobuster dir -u "https://$TARGET" -w "$WORDLIST" -o "$OUTDIR/gobuster.txt";
        ;;
      7)
        dig +noall +answer "$TARGET" > "$OUTDIR/dns_a.txt";
        dig CAA +noall +answer "$TARGET" >> "$OUTDIR/dns_a.txt";
        dig TXT +noall +answer "$TARGET" >> "$OUTDIR/dns_a.txt";
        dig +short TXT "$TARGET" | grep -q "v=spf1" && echo "- SPF record found." >> "$SUMMARY" || echo "- No SPF record found." >> "$SUMMARY"
        ;;
      8)
        echo | openssl s_client -connect "$TARGET:443" -servername "$TARGET" 2>/dev/null \
          | openssl x509 -noout -dates -issuer -subject > "$OUTDIR/cert.txt";
        ;;
      9)
        # recommendations only
        ;;
    esac
    echo "</progress>"
  done
}

# Run the tasks and pipe to whiptail
run_tasks | whiptail --gauge "Security Audit Progress" 10 60 0

# Write recommendations to summary
{
  echo "Security Audit Summary for $TARGET"
  echo "Generated: $(date)"
  echo
  echo "Open TCP ports: $OPEN_TCP"
  if [ "$OPEN_TCP" -gt 3 ]; then
    echo "- WARNING: Consider closing unnecessary TCP ports."
  else
    echo "- TCP port count is within expected range."
  fi
  grep -q "22/tcp.*open" "$OUTDIR/nmap_full.txt" && echo "- SSH (port 22) open: disable root login & enforce key-based auth."
  grep -q "80/tcp.*open" "$OUTDIR/nmap_full.txt" && echo "- HTTP (port 80) open: redirect to HTTPS & enforce HSTS."
  grep -q "443/tcp.*open" "$OUTDIR/nmap_full.txt" && echo "- HTTPS (port 443) open: review weak ciphers in sslscan output."
  echo
  gob_count=$(grep -c "Status: 200" "$OUTDIR/gobuster.txt" || true)
  if [ "$gob_count" -gt 0 ]; then
    echo "- Found $gob_count accessible dirs/files via Gobuster."
  else
    echo "- No common hidden dirs/files found."
  fi
  EXPIRY=$(grep -Po "notAfter=\K.*" "$OUTDIR/cert.txt")
  echo "- Certificate expiration date: $EXPIRY"
  grep -q "issue" "$OUTDIR/dns_a.txt" && echo "- CAA record present." || echo "- No CAA record found."
} >> "$SUMMARY"

# Display summary
whiptail --textbox "$SUMMARY" 20 70

# Display the full path of the results
RESULTS_DIR_FULL_PATH="$(realpath "$OUTDIR")"
SUMMARY_FILE_FULL_PATH="$(realpath "$SUMMARY")"
display_info "Audit completed. Results saved in:\nDirectory: $RESULTS_DIR_FULL_PATH\nSummary File: $SUMMARY_FILE_FULL_PATH"