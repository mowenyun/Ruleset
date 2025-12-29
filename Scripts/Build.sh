#!/usr/bin/env bash

set -euo pipefail

rm -rf Egern Singbox
mkdir -p Egern Singbox
while IFS= read -r -d '' file; do
    relative_path="${file#rule_script/rule/Clash/}"
    relative_dir="$(dirname "$relative_path")"
    mkdir -p "Egern/$relative_dir" "Singbox/$relative_dir"
    cp "$file" "Egern/${relative_path%.list}.yaml"
    cp "$file" "Singbox/${relative_path%.list}.json"
done < <(find rule_script/rule/Clash -mindepth 1 -type f -name "*.list" -print0)

echo "All Ruleset Processed!"