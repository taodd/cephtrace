#!/bin/bash
set -euo pipefail

# 🧾 Usage check
if [[ $# -ne 1 ]]; then
	  echo "Usage: $0 <Launchpad +files page URL>"
	    echo "Example:"
	      echo "  $0 https://launchpad.net/~ubuntu-security-proposed/+archive/ubuntu/ppa/+build/27668892/+files"
	        exit 1
fi

URL="$1"

# 📁 Output directory
OUT_DIR="launchpad_downloads"
mkdir -p "$OUT_DIR"
cd "$OUT_DIR"

echo "[+] Fetching .deb and selected .ddeb links from: $URL"

# Fetch HTML once
html=$(wget -qO- "$URL")

# Extract .deb links (all .deb files, excluding .ddeb)
echo "$html" | \
	  grep -Eo 'https://[a-zA-Z0-9.-]*launchpad.net[^"]+\.deb(">[^<]*)?' | \
	    grep -v '\.ddeb' | \
	      sed 's/">.*//' | \
	        sort -u > deb_urls.txt

# Extract .ddeb links (only for librbd1 or librados2)
echo "$html" | \
	  grep -Eo 'https://[a-zA-Z0-9.-]*launchpad.net[^"]+\.ddeb(">[^<]*)?' | \
	    sed 's/">.*//' | \
	      grep -E 'librbd1|librados2' | \
	        sort -u > ddeb_urls.txt

# Combine all into one file
cat deb_urls.txt ddeb_urls.txt > all_urls.txt

echo "[+] Found $(wc -l < deb_urls.txt) .deb and $(wc -l < ddeb_urls.txt) selected .ddeb files. Downloading..."

# 📥 Download all
wget --content-disposition -c -i all_urls.txt

echo "[✓] All requested files downloaded to: $(pwd)"

echo "Installing.."


