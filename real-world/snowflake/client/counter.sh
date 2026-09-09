#!/bin/bash

# Usage: ./counter.sh proxy_ASNs.csv
INPUT_FILE="$1"
if [[ -z "$INPUT_FILE" ]]; then
  echo "Usage: ./counter.sh input.csv"
  exit 1
fi

# Extract the second column, get unique entries, and count them
unique=$(cut -d',' -f2 "$INPUT_FILE" | sort | uniq | wc -l)
echo "Unique: $unique"

# Total num lines
total=$(wc -l < "$INPUT_FILE")
echo "Total: $total"

# Extract the most repeated hash, ASN pair
result=$(awk -F ',' '{print $2, $3}' "$INPUT_FILE" | sort | uniq -c | sort -nr | head -n 1)

# Parse fields
count=$(echo "$result" | awk '{print $1}')
asn=$(echo "$result" | awk '{print $3}')

echo "Most repeated hash's ASN: $asn"
echo "Num repetitions: $count"