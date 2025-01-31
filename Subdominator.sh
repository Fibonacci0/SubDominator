#!/bin/bash

# Check if target is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <target_domain>"
    exit 1
fi

# Display banner
figlet "SubDominator"

# Define target domain
TARGET="$1"

# Create output directories
OUTPUT_DIR="./subdomain_results_$TARGET"
WAYBACK_FILE="$OUTPUT_DIR/wayback_subdomains.txt"
ALL_SUBDOMAINS="$OUTPUT_DIR/all_subdomains.txt"
RESOLVED_SUBDOMAINS="$OUTPUT_DIR/resolved_subdomains.txt"
mkdir -p $OUTPUT_DIR

# Function to display found subdomains in real-time
display_subdomain() {
    echo "[+] Found subdomain: $1"
}

# Enumerate subdomains with amass
echo "[*] Enumerating subdomains using amass..."
amass enum -d $TARGET -o "$OUTPUT_DIR/amass_subdomains.txt" &>/dev/null &
wait
cat "$OUTPUT_DIR/amass_subdomains.txt" | while read sub; do display_subdomain $sub; done

# Enumerate subdomains with subfinder
echo "[*] Enumerating subdomains using subfinder..."
subfinder -d $TARGET -silent -o "$OUTPUT_DIR/subfinder_subdomains.txt" &
wait
cat "$OUTPUT_DIR/subfinder_subdomains.txt" | while read sub; do display_subdomain $sub; done

# Get subdomains from Wayback Machine
echo "[*] Extracting subdomains from the Wayback Machine..."
curl -s "https://web.archive.org/cdx/search/cdx?url=*.$TARGET/*&collapse=urlkey&output=text&fl=original" \
    | grep -oP "https?://\K[^/]+" \
    | grep -i "$TARGET" \
    | sort -u > $WAYBACK_FILE
cat $WAYBACK_FILE | while read sub; do display_subdomain $sub; done

# Get subdomains from VirusTotal
echo "[*] Collecting subdomains from VirusTotal..."
virustotal_api_key="982680b1787fa59701919aa22515a025e00df1e3bb2bc4f186b8e919558d576c"
curl -s "https://www.virustotal.com/vtapi/v2/domain/report?apikey=$virustotal_api_key&domain=$TARGET" | \
    jq -r '.subdomains[]' > "$OUTPUT_DIR/virustotal_subdomains.txt"
cat "$OUTPUT_DIR/virustotal_subdomains.txt" | while read sub; do display_subdomain $sub; done

# Get subdomains from AlienVault OTX
echo "[*] Collecting URLs from AlienVault OTX..."
curl -s "https://otx.alienvault.com/api/v1/indicators/hostname/$TARGET/url_list?limit=500&page=1" | \
    jq -r '.url_list[].url' > "$OUTPUT_DIR/otx_urls.txt"
grep -oP "https?://\K[^/]+" "$OUTPUT_DIR/otx_urls.txt" | sort -u > "$OUTPUT_DIR/otx_subdomains.txt"
cat "$OUTPUT_DIR/otx_subdomains.txt" | while read sub; do display_subdomain $sub; done

# Consolidate all subdomains
echo "[*] Consolidating all subdomains..."
cat "$OUTPUT_DIR/"*.txt | sort -u > $ALL_SUBDOMAINS
echo "[*] Found $(wc -l < $ALL_SUBDOMAINS) unique subdomains."

# DNS resolution check
echo "[*] Resolving subdomains to filter valid ones..."
while read subdomain; do
    if ping -c 1 -W 1 $subdomain &>/dev/null; then
        echo $subdomain >> $RESOLVED_SUBDOMAINS
        display_subdomain $subdomain
    fi
done < $ALL_SUBDOMAINS
echo "[*] Found $(wc -l < $RESOLVED_SUBDOMAINS) resolved subdomains."

# Capture subdomains with EyeWitness
echo "[*] Capturing subdomains with EyeWitness..."
eyewitness --web --threads 10 -f $RESOLVED_SUBDOMAINS -d "$OUTPUT_DIR/eyewitness_report" &>/dev/null

echo "[*] EyeWitness report saved to $OUTPUT_DIR/eyewitness_report"

