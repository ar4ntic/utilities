#!/usr/bin/env bash
# vm_security_audit.sh - GUI-based Automated security audit for a public-exposed VM
# Uses Zenity for GUI dialogs to prompt the user, install dependencies, run checks, and display results.

# Ensure Zenity is installed
if ! command -v zenity &> /dev/null; then
  echo "Zenity is not installed. Attempting to install it now..."
  if command -v apt-get &> /dev/null; then
    sudo apt-get update && sudo apt-get install -y zenity
  elif command -v yum &> /dev/null; then
    sudo yum install -y zenity
  elif command -v dnf &> /dev/null; then
    sudo dnf install -y zenity
  elif command -v brew &> /dev/null; then
    brew install zenity
  else
    echo "No supported package manager found. Please install Zenity manually and re-run the script."
    exit 1
  fi
fi

# Exit on error and handle failures gracefully
set -e
trap 'zenity --error --title="Error" --text="An unexpected error occurred. Please check logs in the output directory for details."; exit 1' ERR

# Required CLI tools
REQUIRED=(nmap nikto sslscan gobuster dig openssl curl zenity)
MISSING=()
for tool in "${REQUIRED[@]}"; do
  command -v "$tool" >/dev/null 2>&1 || MISSING+=("$tool")
done

# If any tools missing, ask via GUI
if [ ${#MISSING[@]} -gt 0 ]; then
  TO_INSTALL=$(printf "%s\n" "${MISSING[@]}")
  zenity --question --title="Missing Tools" --text="The following tools are missing:\n$TO_INSTALL\n\nInstall them now?"
  if [ $? -eq 0 ]; then
    if command -v apt-get &> /dev/null; then
      sudo apt-get update && sudo apt-get install -y "${MISSING[@]}"
    elif command -v yum &> /dev/null; then
      sudo yum install -y "${MISSING[@]}"
    elif command -v dnf &> /dev/null; then
      sudo dnf install -y "${MISSING[@]}"
    elif command -v brew &> /dev/null; then
      brew install "${MISSING[@]}"
    else
      zenity --error --title="Package Manager Not Found" --text="No supported package manager found. Please install: $TO_INSTALL manually."
      exit 1
    fi
  else
    zenity --error --title="Cannot Continue" --text="Required tools missing: $TO_INSTALL. Exiting."
    exit 1
  fi
fi

# Prompt for target URL/IP
TARGET_RAW=$(zenity --entry --title="Server Security Audit" --text="Enter the target URL or IP address:")
# Validate input: allow only hostname or IPv4/IPv6
if [[ ! "$TARGET_RAW" =~ ^(([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}|[0-9]{1,3}(\.[0-9]{1,3}){3}|\[[0-9a-fA-F:]+\])$ ]]; then
  zenity --error --title="Invalid Input" --text="The entered target '$TARGET_RAW' is not a valid hostname or IP address."
  exit 1
fi
TARGET="$TARGET_RAW"

# Prepare sanitized output directory name
SAFE_TARGET=$(echo "$TARGET" | sed 's/[^a-zA-Z0-9]/_/g')
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTDIR="audit_${SAFE_TARGET}_$TIMESTAMP"
while [ -d "$OUTDIR" ]; do
  TIMESTAMP=$(date +%Y%m%d_%H%M%S)
  OUTDIR="audit_${SAFE_TARGET}_$TIMESTAMP"
done
mkdir -p "$OUTDIR"
SUMMARY="$OUTDIR/summary.txt"
LOGFILE="$OUTDIR/audit.log"
exec > >(tee -a "$LOGFILE") 2>&1

# Default Gobuster wordlist and validation
DEFAULT_WORDLIST="/usr/share/wordlists/dirb/common.txt"
if [ -f "$DEFAULT_WORDLIST" ]; then
  WORDLIST="$DEFAULT_WORDLIST"
else
  WORDLIST=$(zenity --file-selection --title="Select Gobuster wordlist" --file-filter="*.txt" --filename="$HOME/")
  if [ -z "$WORDLIST" ] || [ ! -f "$WORDLIST" ]; then
    zenity --error --title="Wordlist Missing" --text="No valid wordlist selected. Exiting."
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

# Run the tasks and pipe to zenity
run_tasks | zenity --progress --title="Security Audit" --auto-close --percentage=0 --auto-kill \
  --width=500 --height=100 --text="Initializing..."

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
zenity --text-info --title="Audit Summary" --filename="$SUMMARY" --width=600 --height=400