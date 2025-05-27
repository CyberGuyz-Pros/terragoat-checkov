#!/usr/bin/env python3
"""
Checkov JSON to CSV Converter
Converts Checkov security scan results from JSON to structured CSV format
"""

import json
import csv
import os
import sys
from datetime import datetime
from pathlib import Path
import pandas as pd

def load_checkov_report(json_file_path):
    """Load and parse Checkov JSON report"""
    try:
        with open(json_file_path, 'r', encoding='utf-8') as file:
            return json.load(file)
    except FileNotFoundError:
        print(f"❌ Error: Checkov report file not found: {json_file_path}")
        return None
    except json.JSONDecodeError as e:
        print(f"❌ Error: Invalid JSON format in {json_file_path}: {e}")
        return None

def extract_security_findings(checkov_data):
    """Extract security findings from Checkov data"""
    findings = []
    
    if not checkov_data or 'results' not in checkov_data:
        print("⚠️ Warning: No results found in Checkov report")
        return findings
    
    results = checkov_data['results']
    scan_timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # Process failed checks
    failed_checks = results.get('failed_checks', [])
    print(f"📊 Processing {len(failed_checks)} failed security checks...")
    
    for check in failed_checks:
        finding = {
            'timestamp': scan_timestamp,
            'status': 'FAILED',
            'check_id': check.get('check_id', 'N/A'),
            'check_name': check.get('check_name', 'N/A'),
            'check_type': check.get('check_type', 'N/A'),
            'severity': determine_severity(check.get('check_id', '')),
            'file_path': check.get('file_path', 'N/A'),
            'file_line_range': format_line_range(check.get('file_line_range', [])),
            'resource_type': check.get('resource', 'N/A'),
            'resource_name': extract_resource_name(check.get('resource', '')),
            'description': check.get('description', 'N/A'),
            'guideline': check.get('guideline', 'N/A'),
            'fix_definition': check.get('fixed_definition', 'N/A'),
            'code_block': format_code_block(check.get('code_block', [])),
            'category': categorize_check(check.get('check_id', '')),
            'compliance_frameworks': ', '.join(check.get('bc_check_id', '').split('_')[1:3]) if check.get('bc_check_id') else 'N/A'
        }
        findings.append(finding)
    
    # Process passed checks for summary
    passed_checks = results.get('passed_checks', [])
    print(f"✅ {len(passed_checks)} checks passed")
    
    # Add summary information
    if findings:
        print(f"❌ {len(findings)} security issues found")
        severity_counts = {}
        for finding in findings:
            severity = finding['severity']
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        print("📈 Issues by severity:")
        for severity, count in sorted(severity_counts.items()):
            print(f"   {severity}: {count}")
    
    return findings

def determine_severity(check_id):
    """Determine severity based on check ID patterns"""
    if not check_id:
        return 'MEDIUM'
    
    # Critical security issues
    critical_patterns = [
        'CKV_AZURE_1',   # Storage account secure transfer
        'CKV_AZURE_3',   # Storage account public access
        'CKV_AZURE_33',  # Storage account public blob access
        'CKV_AZURE_35',  # Storage account default network access
        'CKV_AZURE_36',  # Storage account trusted service access
        'CKV_AZURE_59',  # Storage account public network access
        'CKV_AZURE_2',   # Storage account encryption
        'CKV_AZURE_8',   # Key Vault purge protection
        'CKV_AZURE_42',  # Key Vault soft delete
        'CKV_AZURE_109', # AKS node public IP
        'CKV_AZURE_115', # AKS network policy
        'CKV_AZURE_4',   # AKS RBAC
        'CKV_AZURE_5',   # AKS monitoring
        'CKV_AZURE_6',   # AKS network plugin
        'CKV_AZURE_7',   # AKS private cluster
    ]
    
    # High severity issues
    high_patterns = [
        'CKV_AZURE_9',   # App Service HTTPS only
        'CKV_AZURE_13',  # App Service TLS version
        'CKV_AZURE_14',  # App Service authentication
        'CKV_AZURE_15',  # App Service client certificates
        'CKV_AZURE_16',  # App Service FTP
        'CKV_AZURE_17',  # App Service managed identity
        'CKV_AZURE_18',  # App Service HTTP2
        'CKV_AZURE_88',  # App Service public network access
        'CKV_AZURE_71',  # Application gateway SSL policy
        'CKV_AZURE_120', # Application gateway WAF
        'CKV_AZURE_122', # Network security group SSH
        'CKV_AZURE_77',  # Network security group RDP
    ]
    
    if check_id in critical_patterns:
        return 'CRITICAL'
    elif check_id in high_patterns:
        return 'HIGH'
    elif 'AZURE' in check_id and any(x in check_id for x in ['ENCRYPT', 'TLS', 'SSL', 'AUTH', 'RBAC']):
        return 'HIGH'
    elif 'AZURE' in check_id and any(x in check_id for x in ['LOG', 'MONITOR', 'BACKUP']):
        return 'MEDIUM'
    else:
        return 'MEDIUM'

def categorize_check(check_id):
    """Categorize the check based on service/resource type"""
    if not check_id:
        return 'General'
    
    categories = {
        'STORAGE': ['CKV_AZURE_1', 'CKV_AZURE_2', 'CKV_AZURE_3', 'CKV_AZURE_33', 'CKV_AZURE_35', 'CKV_AZURE_36', 'CKV_AZURE_59'],
        'KEY_VAULT': ['CKV_AZURE_8', 'CKV_AZURE_42'],
        'AKS': ['CKV_AZURE_4', 'CKV_AZURE_5', 'CKV_AZURE_6', 'CKV_AZURE_7', 'CKV_AZURE_109', 'CKV_AZURE_115'],
        'APP_SERVICE': ['CKV_AZURE_9', 'CKV_AZURE_13', 'CKV_AZURE_14', 'CKV_AZURE_15', 'CKV_AZURE_16', 'CKV_AZURE_17', 'CKV_AZURE_18', 'CKV_AZURE_88'],
        'APPLICATION_GATEWAY': ['CKV_AZURE_71', 'CKV_AZURE_120'],
        'NETWORK_SECURITY': ['CKV_AZURE_77', 'CKV_AZURE_122'],
        'SQL': ['CKV_AZURE_23', 'CKV_AZURE_24', 'CKV_AZURE_25', 'CKV_AZURE_26', 'CKV_AZURE_27'],
        'COMPUTE': ['CKV_AZURE_1', 'CKV_AZURE_37', 'CKV_AZURE_38', 'CKV_AZURE_39']
    }
    
    for category, check_ids in categories.items():
        if check_id in check_ids:
            return category
    
    # Fallback categorization based on service name patterns
    if 'STORAGE' in check_id.upper():
        return 'STORAGE'
    elif 'AKS' in check_id.upper() or 'KUBERNETES' in check_id.upper():
        return 'AKS'
    elif 'APP' in check_id.upper() or 'WEB' in check_id.upper():
        return 'APP_SERVICE'
    elif 'SQL' in check_id.upper() or 'DATABASE' in check_id.upper():
        return 'SQL'
    elif 'NETWORK' in check_id.upper() or 'NSG' in check_id.upper():
        return 'NETWORK_SECURITY'
    elif 'VAULT' in check_id.upper() or 'KEY' in check_id.upper():
        return 'KEY_VAULT'
    else:
        return 'GENERAL'

def extract_resource_name(resource_info):
    """Extract resource name from resource information"""
    if not resource_info or resource_info == 'N/A':
        return 'N/A'
    
    # Resource info might be in format "azurerm_resource.name"
    if '.' in resource_info:
        return resource_info.split('.')[-1]
    return resource_info

def format_line_range(line_range):
    """Format line range for display"""
    if not line_range or len(line_range) == 0:
        return 'N/A'
    if len(line_range) == 1:
        return str(line_range[0])
    return f"{line_range[0]}-{line_range[-1]}"

def format_code_block(code_block):
    """Format code block for CSV (truncate if too long)"""
    if not code_block:
        return 'N/A'
    
    code_str = '\n'.join(code_block) if isinstance(code_block, list) else str(code_block)
    # Truncate long code blocks for CSV readability
    if len(code_str) > 200:
        return code_str[:200] + '...'
    return code_str.replace('\n', ' | ')

def save_to_csv(findings, output_file):
    """Save findings to CSV file"""
    if not findings:
        print("⚠️ No findings to save")
        return False
    
    fieldnames = [
        'timestamp', 'status', 'check_id', 'check_name', 'check_type', 'severity',
        'category', 'file_path', 'file_line_range', 'resource_type', 'resource_name',
        'description', 'guideline', 'fix_definition', 'code_block', 'compliance_frameworks'
    ]
    
    try:
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(findings)
        
        print(f"✅ CSV report saved: {output_file}")
        return True
    except Exception as e:
        print(f"❌ Error saving CSV: {e}")
        return False

def save_to_excel(findings, output_file):
    """Save findings to Excel file with formatting"""
    if not findings:
        print("⚠️ No findings to save to Excel")
        return False
    
    try:
        # Create DataFrame
        df = pd.DataFrame(findings)
        
        # Create Excel writer with formatting
        with pd.ExcelWriter(output_file, engine='openpyxl') as writer:
            # Main findings sheet
            df.to_excel(writer, sheet_name='Security Findings', index=False)
            
            # Summary sheet
            severity_counts = {}
            for finding in findings:
                severity = finding.get('severity', 'UNKNOWN')
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            summary_data = {
                'Metric': ['Total Issues', 'Critical', 'High', 'Medium', 'Low', 'Files Affected', 'Categories Affected'],
                'Count': [
                    len(findings),
                    severity_counts.get('CRITICAL', 0),
                    severity_counts.get('HIGH', 0),
                    severity_counts.get('MEDIUM', 0),
                    severity_counts.get('LOW', 0),
                    len(set(f.get('file_path', 'N/A') for f in findings if f.get('file_path', 'N/A') != 'N/A')),
                    len(set(f.get('category', 'UNKNOWN') for f in findings))
                ]
            }
            
            summary_df = pd.DataFrame(summary_data)
            summary_df.to_excel(writer, sheet_name='Summary', index=False)
            
            # Category breakdown
            category_counts = {}
            for finding in findings:
                cat = finding.get('category', 'UNKNOWN')
                category_counts[cat] = category_counts.get(cat, 0) + 1
            
            if category_counts:
                category_df = pd.DataFrame(list(category_counts.items()), columns=['Category', 'Count'])
                category_df = category_df.sort_values('Count', ascending=False)
                category_df.to_excel(writer, sheet_name='Categories', index=False)
        
        print(f"✅ Excel report saved: {output_file}")
        return True
    except Exception as e:
        print(f"❌ Error saving Excel: {e}")
        return False

def main():
    """Main function"""
    # Get environment variables
    input_json = os.getenv('INPUT_JSON', 'security-reports/checkov-raw-report.json')
    output_csv = os.getenv('OUTPUT_CSV', 'security-reports/terraform-security-report.csv')
    output_excel = os.getenv('OUTPUT_EXCEL', 'security-reports/terraform-security-report.xlsx')
    scan_target = os.getenv('SCAN_TARGET', 'terraform/azure')
    
    print("🔍 Starting Checkov Report Conversion...")
    print(f"📁 Input JSON: {input_json}")
    print(f"📊 Output CSV: {output_csv}")
    print(f"📈 Output Excel: {output_excel}")
    print(f"🎯 Scan Target: {scan_target}")
    print("-" * 50)
    
    # Ensure output directory exists
    try:
        os.makedirs(os.path.dirname(output_csv), exist_ok=True)
    except Exception as e:
        print(f"⚠️ Warning: Could not create output directory: {e}")
    
    # Load Checkov report
    checkov_data = load_checkov_report(input_json)
    if not checkov_data:
        print("❌ Failed to load Checkov report, creating minimal report...")
        # Create minimal report even if JSON is missing
        findings = [{
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'status': 'ERROR',
            'check_id': 'SCAN_ERROR',
            'check_name': 'Failed to load scan results',
            'check_type': 'SYSTEM',
            'severity': 'ERROR',
            'category': 'SYSTEM',
            'file_path': input_json,
            'file_line_range': 'N/A',
            'resource_type': 'N/A',
            'resource_name': 'N/A',
            'description': 'Could not load Checkov JSON report',
            'guideline': 'Check workflow logs for Checkov scan errors',
            'fix_definition': 'N/A',
            'code_block': 'N/A',
            'compliance_frameworks': 'N/A'
        }]
    else:
        # Extract findings
        findings = extract_security_findings(checkov_data)
        
        if not findings:
            print("✅ No security issues found! Creating success report...")
            # Create success report
            findings = [{
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'status': 'NO_ISSUES',
                'check_id': 'SCAN_SUCCESS',
                'check_name': 'No security issues found',
                'check_type': 'SUMMARY',
                'severity': 'INFO',
                'category': 'SUMMARY',
                'file_path': scan_target,
                'file_line_range': 'N/A',
                'resource_type': 'N/A',
                'resource_name': 'N/A',
                'description': 'All security checks passed successfully',
                'guideline': 'N/A',
                'fix_definition': 'N/A',
                'code_block': 'N/A',
                'compliance_frameworks': 'N/A'
            }]
    
    # Save reports
    csv_success = save_to_csv(findings, output_csv)
    
    try:
        excel_success = save_to_excel(findings, output_excel)
    except Exception as e:
        print(f"⚠️ Warning: Could not create Excel report: {e}")
        excel_success = False
    
    if csv_success:
        print(f"📋 CSV Report Details:")
        print(f"   • Total findings: {len(findings)}")
        if os.path.exists(output_csv):
            print(f"   • File size: {os.path.getsize(output_csv)} bytes")
    
    if excel_success and os.path.exists(output_excel):
        print(f"📊 Excel Report Details:")
        print(f"   • File size: {os.path.getsize(output_excel)} bytes")
        print(f"   • Sheets: Security Findings, Summary, Categories")
    
    print("\n🎉 Report conversion completed!")

if __name__ == "__main__":
    main()
