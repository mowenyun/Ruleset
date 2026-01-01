#!/usr/bin/env python3

import json
import sys
import shutil
import argparse
from pathlib import Path
from collections import defaultdict

EGERN_RULE_MAP = {
    "DOMAIN": "domain_set",
    "DOMAIN-SUFFIX": "domain_suffix_set",
    "DOMAIN-KEYWORD": "domain_keyword_set",
    "DOMAIN-WILDCARD": "domain_wildcard_set",
    "IP-CIDR": "ip_cidr_set",
    "IP-CIDR6": "ip_cidr6_set"
}
EGERN_RULE_QUOTE = {"domain_wildcard_set"}

SINGBOX_RULE_MAP = {
    "DOMAIN": "domain",
    "DOMAIN-SUFFIX": "domain_suffix",
    "DOMAIN-KEYWORD": "domain_keyword",
    "IP-CIDR": "ip_cidr",
    "IP-CIDR6": "ip_cidr"
}

def rules_copy():
    source_path = Path("ios_rule_script/rule/Clash")
    egern_path, singbox_path = Path("Egern"), Path("Singbox")
    for path in (egern_path, singbox_path):
        if path.exists():
            shutil.rmtree(path)
        path.mkdir(parents=True, exist_ok=True)
    for file_path in source_path.rglob("*.list"):
        relative = file_path.relative_to(source_path)
        for base, suffix in ((egern_path, ".yaml"), (singbox_path, ".json")):
            target = base / relative.with_suffix(suffix)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(file_path, target)
    print("All Ruleset Processed!")

def rules_load(file_path: Path):
    rule_data = []
    for line in file_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(",", 2)
        while len(parts) < 3:
            parts.append("")
        rule_data.append(tuple(parts[:3]))
    return rule_data

def rules_write(file_path, rule_name=None, rule_count=None, rule_data=None, platform=None):
    with file_path.open("w", encoding="utf-8", newline="\n") as f:
        if platform == "Singbox":
            json.dump(rule_data, f, indent=2, ensure_ascii=False)
            f.write("\n")
        else:
            f.write(f"# 规则名称: {rule_name}\n")
            f.write(f"# 规则统计: {rule_count}\n\n")
            f.writelines(f"{line}\n" for line in rule_data)
    if platform:
        print(f"Processed ({platform}): {file_path}")

def process_egern(file_path: Path):
    rule_name = file_path.stem
    parsed = rules_load(file_path)
    rule_data = defaultdict(list)
    no_resolve = False
    for style, value, field in parsed:
        if style in EGERN_RULE_MAP:
            no_resolve |= field == "no-resolve"
            rule_type = EGERN_RULE_MAP[style]
            rule_value = f'"{value}"' if rule_type in EGERN_RULE_QUOTE else value
            rule_data[rule_type].append(rule_value)
    output = ["no_resolve: true"] if no_resolve else []
    for rule_type, rule_list in rule_data.items():
        output.append(f"{rule_type}:")
        output.extend(f"  - {value}" for value in rule_list)
    rule_count = sum(line.startswith("  - ") for line in output)
    rules_write(file_path, rule_name, rule_count, output, platform="Egern")
    platform_root = next(p for p in file_path.parents if p.name == "Egern")
    relative_path = file_path.relative_to(platform_root.parent)
    readme_file = file_path.parent / "readme.md"
    with readme_file.open("w", encoding="utf-8", newline="\n") as f:
        f.write(f"# 🧸 {rule_name}\n\n")
        f.write(f"https://raw.githubusercontent.com/Centralmatrix3/Ruleset/master/{relative_path.as_posix()}")

def process_singbox(file_path: Path):
    rule_name = file_path.stem
    parsed = rules_load(file_path)
    rule_data = defaultdict(list)
    for style, value, _ in parsed:
        if style in SINGBOX_RULE_MAP:
            rule_type = SINGBOX_RULE_MAP[style]
            rule_data[rule_type].append(value)
    rule_list = [{rule_type: value} for rule_type, value in rule_data.items()]
    output = {"version": 3, "rules": rule_list}
    rules_write(file_path, rule_data=output, platform="Singbox")
    platform_root = next(p for p in file_path.parents if p.name == "Singbox")
    json_relative = file_path.relative_to(platform_root.parent)
    srs_relative = file_path.with_suffix(".srs").relative_to(platform_root.parent)
    readme_file = file_path.parent / "readme.md"
    with readme_file.open("w", encoding="utf-8") as f:
        f.write(f"# 🧸 {rule_name}\n\n")
        f.write(f"https://raw.githubusercontent.com/Centralmatrix3/Ruleset/master/{json_relative.as_posix()}\n\n")
        f.write(f"https://raw.githubusercontent.com/Centralmatrix3/Ruleset/master/{srs_relative.as_posix()}")

def main():
    parser = argparse.ArgumentParser("规则转换脚本")
    parser.add_argument("platform", nargs="?", choices=["Egern", "Singbox"])
    parser.add_argument("file_path", nargs="?", type=Path)
    args = parser.parse_args()
    if not args.platform:
        return rules_copy()
    process_func = {"Egern": process_egern, "Singbox": process_singbox}[args.platform]
    path = args.file_path
    if not path or not path.exists():
        sys.exit(f"{path} not found or unsupported type.")
    files = [path] if path.is_file() else sorted(f for f in path.rglob("*") if f.is_file())
    if not files:
        print(f"No files found in: {path}")
        return
    for f in files:
        try: process_func(f)
        except Exception as e: print(f"Failed to process {f}: {e}")
    print("Processed Completed.")

if __name__ == "__main__":
    main()