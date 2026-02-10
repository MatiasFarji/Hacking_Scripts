#!/usr/bin/env python3
"""
Burp Suite Configuration Generator (Interactive)

Generates a Burp Suite project configuration JSON from user input.
Prompts for target name, domains, and custom headers interactively.

Usage:
    python burpsuite_configure.py
"""

import json
import re
import sys
from pathlib import Path


def get_script_dir() -> Path:
    """Get the directory where this script is located."""
    return Path(__file__).resolve().parent


def domain_to_burp_host_regex(domain: str) -> str:
    """
    Convert a domain to a Burp Suite host regex pattern.
    
    Example: "example.com" -> "^(.+\\.)?example\\.com$"
    This matches the domain and all its subdomains.
    """
    domain = domain.strip()
    
    # Remove scheme if present
    domain = re.sub(r'^https?://', '', domain, flags=re.IGNORECASE)
    
    # Remove trailing slash and port
    domain = domain.rstrip('/')
    domain = re.sub(r':\d+$', '', domain)
    
    if not domain:
        return ''
    
    # Escape special regex characters
    escaped = re.escape(domain)
    
    # Allow exact domain or subdomains
    return f'^(.+\\.)?{escaped}$'


def normalize_domain(domain: str) -> str:
    """Normalize a domain string."""
    domain = domain.strip()
    
    # Remove scheme, port, path
    domain = re.sub(r'^https?://', '', domain, flags=re.IGNORECASE)
    domain = re.sub(r'[:/].*$', '', domain)
    
    return domain.lower()


def build_scope_include(domains: list[str]) -> list[dict]:
    """Build Burp scope include rules for all domains."""
    include = []
    
    protocols = [
        {'protocol': 'http', 'port': '^80$'},
        {'protocol': 'https', 'port': '^443$'},
    ]
    
    for domain in domains:
        host_regex = domain_to_burp_host_regex(domain)
        if not host_regex:
            continue
        
        for proto in protocols:
            include.append({
                'enabled': True,
                'file': '^/.*',
                'host': host_regex,
                'port': proto['port'],
                'protocol': proto['protocol'],
            })
    
    return include


def build_header_actions(headers: list[dict]) -> list[dict]:
    """Build header actions for session handling rules."""
    actions = []
    
    for header in headers:
        actions.append({
            'add_if_not_present': True,
            'enabled': True,
            'name': header['name'],
            'type': 'set_header',
            'value': header['value'],
        })
    
    return actions


def build_burp_config(include: list[dict], headers: list[dict], exclude: list[dict] = None) -> dict:
    """Build complete Burp Suite configuration."""
    if exclude is None:
        exclude = []
    
    # Build session handling rules
    rules = [
        {
            'actions': [
                {
                    'enabled': True,
                    'match_cookies': 'all_except',
                    'type': 'use_cookies',
                }
            ],
            'description': "Use cookies from Burp's cookie jar",
            'enabled': True,
            'exclude_from_scope': [],
            'include_in_scope': [],
            'named_params': [],
            'restrict_scope_to_named_params': False,
            'tools_scope': ['Scanner'],
            'url_scope': 'all',
            'url_scope_advanced_mode': False,
        },
    ]
    
    # Add custom headers rule if headers exist
    if headers:
        rules.append({
            'actions': build_header_actions(headers),
            'description': 'Add Custom Headers',
            'enabled': True,
            'exclude_from_scope': [],
            'include_in_scope': [],
            'named_params': [],
            'restrict_scope_to_named_params': False,
            'tools_scope': [
                'Target', 'Proxy', 'Scanner', 'Intruder',
                'Repeater', 'Sequencer', 'Burp AI'
            ],
            'url_scope': 'suite',
            'url_scope_advanced_mode': False,
        })
    
    return {
        'target': {
            'scope': {
                'advanced_mode': True,
                'exclude': exclude,
                'include': include,
            },
        },
        'project_options': {
            'connections': {
                'out_of_scope_requests': {
                    'advanced_mode': False,
                    'drop_all_out_of_scope': False,
                    'exclude': [],
                    'include': [],
                    'scope_option': 'suite',
                },
                'platform_authentication': {
                    'credentials': [],
                    'do_platform_authentication': True,
                    'prompt_on_authentication_failure': False,
                    'use_user_options': True,
                },
                'socks_proxy': {
                    'dns_over_socks': False,
                    'host': '',
                    'password': '',
                    'port': 0,
                    'use_proxy': False,
                    'use_user_options': True,
                    'username': '',
                },
                'timeouts': {
                    'connect_timeout': 120000,
                    'domain_name_resolution_timeout': 300000,
                    'failed_domain_name_resolution_timeout': 60000,
                    'normal_timeout': 120000,
                    'open_ended_response_timeout': 10000,
                },
                'upstream_proxy': {
                    'servers': [
                        {
                            'destination_host': '*',
                            'proxy_host': '127.0.0.1',
                            'proxy_port': 8081,
                            'authentication_type': 'none',
                        }
                    ],
                    'use_user_options': True,
                },
            },
            'sessions': {
                'session_handling_rules': {
                    'rules': rules,
                }
            },
        },
    }


def prompt_target_name() -> str:
    """Prompt user for target name."""
    while True:
        print()
        target = input("Enter target name: ").strip()
        
        if not target:
            print("Error: Target name cannot be empty")
            continue
        
        # Sanitize: only allow alphanumeric, dash, underscore
        if not re.match(r'^[\w\-]+$', target):
            print("Error: Target name can only contain letters, numbers, dashes, and underscores")
            continue
        
        return target


def prompt_domains() -> list[str]:
    """Prompt user for domains, one per line."""
    print()
    print("Enter domains (one per line)")
    print("Press Enter twice or type 'done' when finished:")
    print("-" * 40)
    
    domains = set()
    empty_count = 0
    
    while True:
        try:
            line = input().strip()
        except EOFError:
            break
        
        # Check for exit conditions
        if line.lower() == 'done':
            break
        
        if not line:
            empty_count += 1
            if empty_count >= 2:
                break
            continue
        
        empty_count = 0
        
        # Skip comments
        if line.startswith('#') or line.startswith('//'):
            continue
        
        # Normalize and add domain
        domain = normalize_domain(line)
        if domain:
            domains.add(domain)
            print(f"  + {domain}")
    
    return sorted(domains)


def prompt_headers() -> list[dict]:
    """Prompt user for custom headers."""
    headers = []
    
    print()
    print("=" * 50)
    print("  Custom Headers")
    print("=" * 50)
    
    while True:
        print()
        add_header = input("Add a custom header? [y/N]: ").strip().lower()
        
        if add_header not in ('y', 'yes'):
            break
        
        # Get header name
        while True:
            name = input("  Header name: ").strip()
            if name:
                break
            print("  Error: Header name cannot be empty")
        
        # Get header value
        while True:
            value = input("  Header value: ").strip()
            if value:
                break
            print("  Error: Header value cannot be empty")
        
        headers.append({'name': name, 'value': value})
        print(f"  + {name}: {value}")
    
    return headers


def main():
    base_dir = get_script_dir()
    
    print("=" * 50)
    print("  Burp Suite Configuration Generator")
    print("=" * 50)
    
    # Get target name
    target = prompt_target_name()
    
    # Setup directories
    target_dir = base_dir / target
    target_dir.mkdir(parents=True, exist_ok=True)
    
    domains_file = target_dir / "domains.txt"
    headers_file = target_dir / "headers.txt"
    output_file = target_dir / "burpsuite_config.json"
    
    # Check if domains.txt already exists
    existing_domains = []
    if domains_file.exists():
        print(f"\nFound existing domains.txt in {target}/")
        
        with open(domains_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    domain = normalize_domain(line)
                    if domain:
                        existing_domains.append(domain)
        
        if existing_domains:
            print(f"Existing domains ({len(existing_domains)}):")
            for d in existing_domains:
                print(f"  - {d}")
            
            print()
            choice = input("Use existing domains? [Y/n]: ").strip().lower()
            
            if choice in ('', 'y', 'yes'):
                domains = existing_domains
            else:
                domains = prompt_domains()
        else:
            domains = prompt_domains()
    else:
        domains = prompt_domains()
    
    # Validate we have domains
    if not domains:
        print("\nError: No domains provided", file=sys.stderr)
        sys.exit(1)
    
    # Check if headers.txt already exists
    existing_headers = []
    if headers_file.exists():
        print(f"\nFound existing headers.txt in {target}/")
        
        with open(headers_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and ':' in line:
                    name, value = line.split(':', 1)
                    existing_headers.append({'name': name.strip(), 'value': value.strip()})
        
        if existing_headers:
            print(f"Existing headers ({len(existing_headers)}):")
            for h in existing_headers:
                print(f"  - {h['name']}: {h['value']}")
            
            print()
            choice = input("Use existing headers? [Y/n]: ").strip().lower()
            
            if choice in ('', 'y', 'yes'):
                headers = existing_headers
            else:
                headers = prompt_headers()
        else:
            headers = prompt_headers()
    else:
        headers = prompt_headers()
    
    # Save domains to file
    with open(domains_file, 'w') as f:
        f.write("# Domains for " + target + "\n")
        for domain in domains:
            f.write(domain + "\n")
    
    print(f"\nSaved {len(domains)} domains to: {domains_file}")
    
    # Save headers to file
    if headers:
        with open(headers_file, 'w') as f:
            f.write("# Headers for " + target + "\n")
            for h in headers:
                f.write(f"{h['name']}: {h['value']}\n")
        
        print(f"Saved {len(headers)} headers to: {headers_file}")
    
    # Save target name
    target_file = base_dir / "target.txt"
    with open(target_file, 'w') as f:
        f.write(target)
    
    print(f"Saved target name to: {target_file}")
    
    # Build configuration
    include = build_scope_include(domains)
    config = build_burp_config(include, headers)
    
    # Write JSON
    with open(output_file, 'w') as f:
        json.dump(config, f, indent=2, ensure_ascii=False)
    
    print(f"Generated config: {output_file}")
    
    # Summary
    print()
    print("=" * 50)
    print("  Done!")
    print("=" * 50)
    print(f"  Target:  {target}")
    print(f"  Domains: {len(domains)}")
    print(f"  Headers: {len(headers)}")
    print(f"  Config:  {output_file}")
    print()
    print("Next steps:")
    print(f"  1. Import {output_file} in Burp Suite")
    print("  2. Run: ./chain_mitmproxy.sh")
    print()


if __name__ == "__main__":
    main()