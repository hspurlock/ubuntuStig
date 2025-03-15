#!/usr/bin/env python3
"""
Parse STIG XML file and extract rule information for compliance checks.
"""

import sys
import os
import xml.etree.ElementTree as ET
import json
import re
from collections import defaultdict

def extract_commands_from_check_content(check_content):
    """Extract commands from check content text."""
    commands = []
    
    # Special case for maxlogins check which has problematic regex characters
    if "maxlogins" in check_content and "'^[^#]" in check_content:
        # Extract the command directly to avoid regex escaping issues
        maxlogins_cmd = "grep -r -s \"^[^#].*maxlogins\" /etc/security/limits.conf /etc/security/limits.d/*.conf"
        commands.append(maxlogins_cmd)
        return commands  # Return early as we've handled this special case
    
    # Look for command patterns in the check content
    # Pattern 1: Commands after a $ symbol (common in STIG checks)
    cmd_pattern1 = r'\$\s+(sudo\s+)?([^#\n]+)'
    matches1 = re.finditer(cmd_pattern1, check_content)
    for match in matches1:
        cmd = match.group(2).strip()
        if cmd and len(cmd) > 5:  # Avoid short or incomplete commands
            commands.append(cmd)
    
    # Pattern 2: Commands that are on their own line and look like shell commands
    # This pattern looks for lines that start with common command names
    cmd_pattern2 = r'^(sudo |)(grep|find|ls|ps|cat|systemctl|apt|dpkg|auditctl|sysctl|chmod|chown|stat|ufw|iptables|firewall-cmd|sestatus|ausearch|aureport|getent)[^\n]+$'
    matches2 = re.finditer(cmd_pattern2, check_content, re.MULTILINE)
    for match in matches2:
        cmd = match.group(0).strip()
        if cmd and len(cmd) > 5:  # Avoid short or incomplete commands
            commands.append(cmd)
    
    # Filter out non-command strings and duplicates
    filtered_commands = []
    seen = set()
    
    for cmd in commands:
        # Skip if we've seen this command before
        if cmd in seen:
            continue
        
        # Skip if it's not likely a command
        if not re.match(r'^[a-zA-Z0-9_\-\.]+\s+', cmd):
            continue
            
        # Skip if it contains HTML tags
        if re.search(r'<[^>]+>', cmd):
            continue
            
        # Skip if it's too long (likely not a command)
        if len(cmd) > 200:
            continue
        
        # Skip if it starts with words that indicate it's not a command
        non_command_starters = ['verify', 'check', 'ensure', 'if', 'note', 'the', 'this', 'these', 'those']
        if any(cmd.lower().startswith(word) for word in non_command_starters):
            continue
            
        filtered_commands.append(cmd)
        seen.add(cmd)
    
    return filtered_commands

def determine_requirement_type(rule_description, check_content):
    """Determine if this is a positive or negative requirement."""
    negative_patterns = [
        r'must not have',
        r'must be removed',
        r'must not be installed',
        r'must not be enabled',
        r'must not be running',
        r'must not exist',
        r'must not allow',
        r'must not permit',
        r'must not be present',
        r'must not be configured',
        r'must not be active',
        r'must not be available',
        r'must not be used',
        r'must not be set',
        r'must not contain',
        r'must not include',
        r'must not support',
        r'must not provide',
        r'must not implement',
        r'must not utilize',
        r'must not be accessible',
        r'must not be shared',
        r'must not be open',
        r'must not be world',
        r'must not have.*installed',
        r'must not have.*enabled',
        r'must not have.*running',
        r'must not have.*active',
    ]
    
    # Check title and description for negative patterns
    combined_text = rule_description
    for pattern in negative_patterns:
        if re.search(pattern, combined_text, re.IGNORECASE):
            return "negative"
    
    # Also check the check content for negative patterns
    for pattern in negative_patterns:
        if re.search(pattern, check_content, re.IGNORECASE):
            return "negative"
    
    # Check for specific phrases in check content that indicate negative requirements
    if "is installed" in check_content and "this is a finding" in check_content:
        # First check for positive patterns that might override
        if re.search(r'if no.*installed.*this is a finding', check_content, re.IGNORECASE):
            return "positive"
        if re.search(r'if.*is not installed.*this is a finding', check_content, re.IGNORECASE):
            return "positive"
            
        # Check if this is actually a negative requirement
        # Look for patterns like "If X is installed, this is a finding"
        if re.search(r'if.*is installed.*this is a finding', check_content, re.IGNORECASE):
            return "negative"
    
    # Check for patterns that indicate positive requirements
    if re.search(r'if.*is not installed.*this is a finding', check_content, re.IGNORECASE):
        return "positive"
    if re.search(r'if.*disabled.*this is a finding', check_content, re.IGNORECASE):
        return "positive"
    if re.search(r'if.*inactive.*this is a finding', check_content, re.IGNORECASE):
        return "positive"
    if re.search(r'if no.*installed.*this is a finding', check_content, re.IGNORECASE):
        return "positive"
    
    return "positive"

def determine_check_type(rule_id, rule_title, check_content, commands):
    """Determine the type of check based on the content and commands."""
    # Package check patterns
    package_patterns = [
        r'apt\s+list\s+--installed',
        r'dpkg\s+-l',
        r'apt\s+show',
        r'apt-cache\s+policy',
        r'must not have .* package installed',
        r'must have .* package installed',
    ]
    
    # Service check patterns
    service_patterns = [
        r'systemctl\s+is-active',
        r'systemctl\s+is-enabled',
        r'systemctl\s+status',
        r'service\s+.*\s+status',
        r'must be running',
        r'must be enabled',
        r'must be active',
        r'must not be running',
        r'must not be enabled',
        r'must not be active',
    ]
    
    # Configuration check patterns
    config_patterns = [
        r'grep\s+-i',
        r'cat\s+/etc',
        r'find\s+/etc',
        r'must be set to',
        r'must contain',
        r'must be configured',
        r'configuration',
        r'config',
        r'setting',
        r'option',
        r'parameter',
    ]
    
    # Check for package-related patterns
    for pattern in package_patterns:
        if re.search(pattern, check_content, re.IGNORECASE) or any(re.search(pattern, cmd, re.IGNORECASE) for cmd in commands):
            return "package"
    
    # Check for service-related patterns
    for pattern in service_patterns:
        if re.search(pattern, check_content, re.IGNORECASE) or any(re.search(pattern, cmd, re.IGNORECASE) for cmd in commands):
            return "service"
    
    # Check for configuration-related patterns
    for pattern in config_patterns:
        if re.search(pattern, check_content, re.IGNORECASE) or any(re.search(pattern, cmd, re.IGNORECASE) for cmd in commands):
            return "config"
    
    # Default to generic
    return "generic"

def parse_stig_xml(xml_file):
    """Parse the STIG XML file and extract rule information."""
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
        
        # Define namespace
        ns = {'xccdf': 'http://checklists.nist.gov/xccdf/1.1'}
        
        # Dictionary to store rule information
        rules_info = {}
        
        # Find all Rule elements
        rules = root.findall('.//xccdf:Rule', ns)
        
        for rule in rules:
            rule_id = rule.get('id')
            if not rule_id:
                continue
                
            # Get rule title
            title_elem = rule.find('./xccdf:title', ns)
            title = title_elem.text if title_elem is not None else ""
            
            # Get rule description
            desc_elem = rule.find('./xccdf:description', ns)
            description = desc_elem.text if desc_elem is not None else ""
            
            # The description might contain HTML-like tags that need to be parsed
            # Extract the actual text content from the description
            description = re.sub(r'<[^>]+>', '', description).strip()
            # Remove any trailing "false" or "true" that might be part of the XML structure
            description = re.sub(r'(true|false)$', '', description).strip()
            
            # Get check content
            check_elem = rule.find('.//xccdf:check-content', ns)
            check_content = check_elem.text if check_elem is not None else ""
            
            # The check_content might contain HTML-like tags that need to be parsed
            # Extract the actual text content from the check_content
            check_content = re.sub(r'<[^>]+>', '', check_content).strip()
            
            # Get fix text
            fix_elem = rule.find('./xccdf:fixtext', ns)
            fix_text = fix_elem.text if fix_elem is not None else ""
            
            # Extract commands from check content
            commands = extract_commands_from_check_content(check_content)
            
            # Determine requirement type (positive or negative)
            requirement_type = determine_requirement_type(description, check_content)
            
            # Determine check type
            check_type = determine_check_type(rule_id, title, check_content, commands)
            
            # Store rule information
            rules_info[rule_id] = {
                'title': title,
                'description': description,
                'check_content': check_content,
                'fix_text': fix_text,
                'commands': commands,
                'requirement_type': requirement_type,
                'check_type': check_type
            }
        
        return rules_info
    
    except Exception as e:
        print(f"Error parsing XML file: {e}")
        return {}

def get_rule_info(xml_file, rule_id):
    """Get information for a specific rule."""
    rules_info = parse_stig_xml(xml_file)
    return rules_info.get(rule_id, {})

def get_all_rule_ids(xml_file):
    """Get all rule IDs from the XML file."""
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
        
        # Define namespace
        ns = {'xccdf': 'http://checklists.nist.gov/xccdf/1.1'}
        
        # Find all Rule elements
        rules = root.findall('.//xccdf:Rule', ns)
        
        rule_info = {}
        for rule in rules:
            rule_id = rule.get('id')
            if not rule_id:
                continue
                
            # Get rule title
            title_elem = rule.find('./xccdf:title', ns)
            title = title_elem.text if title_elem is not None else "No title available"
            
            # Get rule description
            desc_elem = rule.find('./xccdf:description', ns)
            desc = desc_elem.text if desc_elem is not None else ""
            
            # The description might contain HTML-like tags that need to be parsed
            # Extract the actual text content from the description
            desc = re.sub(r'<[^>]+>', '', desc).strip()
            # Remove any trailing "false" or "true" that might be part of the XML structure
            desc = re.sub(r'(true|false)$', '', desc).strip()
            
            # Get check content
            check_content = ""
            check_elem = rule.find('.//xccdf:check-content', ns)
            if check_elem is not None:
                check_content = check_elem.text
            
            # The check_content might contain HTML-like tags that need to be parsed
            # Extract the actual text content from the check_content
            check_content = re.sub(r'<[^>]+>', '', check_content).strip()
            
            # Extract commands from check content
            commands = extract_commands_from_check_content(check_content) if check_content else []
            
            # Determine requirement type
            requirement_type = determine_requirement_type(desc, check_content)
            
            # Determine check type
            check_type = determine_check_type(rule_id, title, check_content, commands)
            
            # Add to rule_info dictionary
            rule_info[rule_id] = {
                "title": title,
                "description": desc,
                "check_content": check_content,
                "commands": commands,
                "requirement_type": requirement_type,
                "check_type": check_type
            }
        
        return json.dumps(rule_info, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})

def main():
    """Main function."""
    if len(sys.argv) < 2:
        print("Usage: python parse_stig_xml.py <xml_file> [rule_id] [field_name]")
        print("Fields: title, description, check_content, fix_text, commands, requirement_type, check_type")
        sys.exit(1)
    
    xml_file = sys.argv[1]
    
    # Check if --list-rules flag is present
    if len(sys.argv) > 2 and sys.argv[2] == "--list-rules":
        rules_info = parse_stig_xml(xml_file)
        for rule_id in rules_info:
            print(rule_id)
        sys.exit(0)
    
    if len(sys.argv) > 2:
        rule_id = sys.argv[2]
        
        # If a specific field is requested
        if len(sys.argv) > 3:
            field_name = sys.argv[3]
            rule_info = get_rule_info(xml_file, rule_id)
            
            # Convert from JSON string to dict
            if isinstance(rule_info, str):
                rule_info = json.loads(rule_info)
                
            # Extract the requested field
            if field_name in rule_info:
                if field_name == "commands":
                    print(json.dumps(rule_info[field_name]))
                else:
                    print(rule_info[field_name])
            else:
                print(f"Field '{field_name}' not found in rule {rule_id}")
        else:
            # Return the entire rule info
            rule_info = get_rule_info(xml_file, rule_id)
            print(rule_info)
    else:
        rule_ids = get_all_rule_ids(xml_file)
        print(rule_ids)

if __name__ == "__main__":
    main()
