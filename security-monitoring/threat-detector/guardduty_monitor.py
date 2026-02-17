"""
GuardDuty Findings Monitor
Fetches and analyzes AWS GuardDuty security findings
"""

import boto3
from typing import List, Dict, Any
from datetime import datetime


class GuardDutyMonitor:
    """Monitor and analyze GuardDuty findings"""
    
    def __init__(self, region: str = 'us-east-1'):
        """
        Initialize GuardDuty monitor
        
        Args:
            region: AWS region to monitor
        """
        self.guardduty = boto3.client('guardduty', region_name=region)
        self.region = region
        
    def get_detector_id(self) -> str:
        """
        Get GuardDuty detector ID
        
        Returns:
            Detector ID string or None if not found
        """
        try:
            response = self.guardduty.list_detectors()
            detectors = response.get('DetectorIds', [])
            
            if not detectors:
                print("❌ No GuardDuty detector found")
                print("   Please enable GuardDuty in AWS Console")
                return None
            
            return detectors[0]
            
        except Exception as e:
            print(f"❌ Error getting detector: {str(e)}")
            return None
    
    def get_findings(self, severity_threshold: int = 4, max_results: int = 50) -> List[Dict[str, Any]]:
        """
        Get GuardDuty findings above severity threshold
        
        Args:
            severity_threshold: Minimum severity (0-10, default 4 = medium)
            max_results: Maximum number of findings to retrieve
            
        Returns:
            List of findings
        """
        detector_id = self.get_detector_id()
        if not detector_id:
            return []
        
        print(f"\n{'='*70}")
        print(f"🛡️  GuardDuty Security Findings")
        print(f"{'='*70}")
        print(f"Region: {self.region}")
        print(f"Detector ID: {detector_id}")
        print(f"Severity Threshold: {severity_threshold}/10")
        print(f"{'='*70}\n")
        
        try:
            # List finding IDs with criteria
            list_response = self.guardduty.list_findings(
                DetectorId=detector_id,
                FindingCriteria={
                    'Criterion': {
                        'severity': {
                            'Gte': severity_threshold
                        },
                        'service.archived': {
                            'Eq': ['false']
                        }
                    }
                },
                MaxResults=max_results,
                SortCriteria={
                    'AttributeName': 'severity',
                    'OrderBy': 'DESC'
                }
            )
            
            finding_ids = list_response.get('FindingIds', [])
            
            if not finding_ids:
                print("✅ No security findings found!")
                print("   Your environment is secure.\n")
                return []
            
            print(f"📊 Found {len(finding_ids)} findings above threshold\n")
            
            # Get finding details
            findings_response = self.guardduty.get_findings(
                DetectorId=detector_id,
                FindingIds=finding_ids
            )
            
            findings = findings_response.get('Findings', [])
            return self._parse_findings(findings)
            
        except Exception as e:
            print(f"❌ Error getting findings: {str(e)}")
            return []
    
    def _parse_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Parse and structure GuardDuty findings
        
        Args:
            findings: Raw GuardDuty findings
            
        Returns:
            Structured findings list
        """
        parsed = []
        
        for finding in findings:
            # Get resource info
            resource = finding.get('Resource', {})
            resource_type = resource.get('ResourceType', 'Unknown')
            
            # Get service info
            service = finding.get('Service', {})
            action = service.get('Action', {})
            
            parsed_finding = {
                'id': finding.get('Id'),
                'type': finding.get('Type'),
                'severity': finding.get('Severity'),
                'title': finding.get('Title'),
                'description': finding.get('Description'),
                'created_at': finding.get('CreatedAt'),
                'updated_at': finding.get('UpdatedAt'),
                'resource_type': resource_type,
                'region': finding.get('Region'),
                'confidence': finding.get('Confidence'),
                'action_type': action.get('ActionType', 'Unknown')
            }
            parsed.append(parsed_finding)
        
        return parsed
    
    def categorize_findings(self, findings: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """
        Categorize findings by severity
        
        Args:
            findings: List of findings
            
        Returns:
            Dictionary of categorized findings
        """
        categorized = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': []
        }
        
        for finding in findings:
            severity = finding.get('severity', 0)
            
            if severity >= 7:
                categorized['critical'].append(finding)
            elif severity >= 5:
                categorized['high'].append(finding)
            elif severity >= 3:
                categorized['medium'].append(finding)
            else:
                categorized['low'].append(finding)
        
        return categorized
    
    def generate_summary(self, findings: List[Dict[str, Any]]) -> str:
        """
        Generate summary report
        
        Args:
            findings: List of findings
            
        Returns:
            Formatted report string
        """
        categorized = self.categorize_findings(findings)
        
        report = f"""
╔══════════════════════════════════════════════════════════════════╗
║           GuardDuty Security Findings Summary                    ║
╚══════════════════════════════════════════════════════════════════╝

Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Region: {self.region}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SEVERITY BREAKDOWN
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔴 Critical (7.0-10.0):  {len(categorized['critical']):3d} findings
🟠 High     (5.0-6.9):  {len(categorized['high']):3d} findings
🟡 Medium   (3.0-4.9):  {len(categorized['medium']):3d} findings
🟢 Low      (0.0-2.9):  {len(categorized['low']):3d} findings

Total Findings: {len(findings)}
"""
        
        if categorized['critical']:
            report += "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            report += "⚠️  CRITICAL FINDINGS (IMMEDIATE ACTION REQUIRED)\n"
            report += "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
            
            for finding in categorized['critical'][:5]:
                report += f"Finding Type: {finding['type']}\n"
                report += f"Title: {finding['title']}\n"
                report += f"Severity: {finding['severity']}/10\n"
                report += f"Confidence: {finding['confidence']}/10\n"
                report += f"Resource: {finding['resource_type']}\n"
                report += f"Description: {finding['description'][:200]}...\n"
                report += f"Created: {finding['created_at']}\n"
                report += "─" * 66 + "\n\n"
        
        if categorized['high']:
            report += "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            report += "🟠 HIGH SEVERITY FINDINGS\n"
            report += "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
            
            for finding in categorized['high'][:3]:
                report += f"• {finding['title']}\n"
                report += f"  Type: {finding['type']}\n"
                report += f"  Severity: {finding['severity']}/10\n\n"
        
        report += "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        report += "RECOMMENDATIONS\n"
        report += "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
        
        if categorized['critical']:
            report += "1. ⚠️  URGENT: Address critical findings immediately\n"
            report += "2. Review and quarantine affected resources\n"
            report += "3. Investigate root cause of security events\n"
            report += "4. Update security policies and access controls\n"
        elif categorized['high']:
            report += "1. Review high-severity findings within 24 hours\n"
            report += "2. Validate security controls are functioning\n"
            report += "3. Consider additional monitoring for affected resources\n"
        else:
            report += "1. Continue monitoring GuardDuty findings regularly\n"
            report += "2. Review and archive resolved findings\n"
            report += "3. Maintain proactive security posture\n"
        
        report += "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        
        return report


def main():
    """Main execution function"""
    print("\n" + "="*70)
    print("🛡️  SecureCloud GuardDuty Monitor")
    print("   Enterprise Threat Detection")
    print("="*70)
    
    monitor = GuardDutyMonitor()
    
    try:
        # Get findings
        findings = monitor.get_findings(severity_threshold=4, max_results=50)
        
        if findings:
            # Generate summary
            summary = monitor.generate_summary(findings)
            print(summary)
            
            # Save report
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"guardduty_report_{timestamp}.txt"
            
            with open(filename, 'w') as f:
                f.write(summary)
            
            print(f"\n📄 Report saved to: {filename}")
        
        print("\n" + "="*70)
        print("Analysis complete!")
        print("="*70 + "\n")
        
    except Exception as e:
        print(f"\n❌ Fatal Error: {str(e)}")
        print("\nTroubleshooting:")
        print("1. Ensure AWS credentials are configured: aws configure")
        print("2. Verify GuardDuty is enabled in your AWS account")
        print("3. Check IAM permissions for GuardDuty access")
        print()


if __name__ == "__main__":
    main()
