#!/usr/bin/env python3
import re
import os
import sys

def patch_file(filepath):
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()

    original = content

    # Replace full WindowsPrincipal cast + IsInRole in one shot
    # Pattern: ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(...)
    content = re.sub(
        r'\(\s*\[(?:System\.)?Security\.Principal\.WindowsPrincipal\]\s*\[(?:System\.)?Security\.Principal\.WindowsIdentity\]::GetCurrent\(\)\s*\)\.IsInRole\([^)]*\)',
        '$false',
        content
    )

    # Replace remaining WindowsPrincipal cast expression (without IsInRole)
    content = re.sub(
        r'\[(?:System\.)?Security\.Principal\.WindowsPrincipal\]\s*\[(?:System\.)?Security\.Principal\.WindowsIdentity\]::GetCurrent\(\)',
        '$false',
        content
    )

    # Replace bare WindowsIdentity::GetCurrent() calls
    content = re.sub(
        r'\[(?:System\.)?Security\.Principal\.WindowsIdentity\]::GetCurrent\(\)',
        '"Linux-Container"',
        content
    )

    # Fix any leftover ($null).Equals($false) introduced by previous bad patches
    content = re.sub(
        r'\(\s*\$null\s*\)\.Equals\(\s*\$false\s*\)',
        '$false',
        content
    )

    # Fix $null.IsInRole(...) 
    content = re.sub(
        r'\$null\.IsInRole\([^)]*\)',
        '$false',
        content
    )

    if content != original:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"Patched: {filepath}")

def main():
    search_dir = sys.argv[1] if len(sys.argv) > 1 else '/tmp/scubagear-src'
    for root, dirs, files in os.walk(search_dir):
        for fname in files:
            if fname.endswith(('.ps1', '.psm1', '.psd1')):
                patch_file(os.path.join(root, fname))

if __name__ == '__main__':
    main()