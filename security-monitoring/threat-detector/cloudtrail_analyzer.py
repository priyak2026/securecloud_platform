"""
CloudTrail Log Analyzer for Threat Detection
Analyzes AWS CloudTrail logs for suspicious security events
"""

import boto3
from datetime import datetime, timedelta
from typing import List, Dict, Any
import os


class CloudTrailAnalyzer:
    """Analyze CloudTrail logs for security threats"""
    
    def __init__(self, region: str = 'us-east-1'):
        """
        Initialize CloudTrail analyzer
        
        Args:
            region: AWS region to analyze
        """
        self.region = region
        self.cloudtrail = boto3.client('cloudtrail', region_name=region)
        
        # Suspicious events to monitor
        self.suspicious_events = [
            'DeleteBucket',
            'PutBucketPolicy',
            'CreateAccessKey',
            'DeleteTrail',
            'StopLogging',
            'ModifyDBInstance',
            'AuthorizeSecurityGroupIngress',
            'AuthorizeSecurityGroupEgress',
            'CreateUser',
            'AttachUserPolicy',
            'PutUserPolicy',
            'DeleteUser',
            'ConsoleLogin'
        ]
    
    def analyze_recent_events(self, hours: int = 24) -> List[Dict[str, Any]]:
        """
        Analyze CloudTrail events from the last N hours
        
        Args:
            hours: Number of hours to look back (default: 24)
            
        Returns:
            List of suspicious events found
        """
        print(f"\n{'='*70}")
        print(f"🔍 CloudTrail Security Analysis")
        print(f"{'='*70}")
        print(f"Region: {self.region}")
        print(f"Analysis Period: Last {hours} hours")
        print(f"Monitoring {len(self.suspicious_events)} event types")
        print(f"{'='*70}\n")
        
        end_time = datetime.now()
        start_time = end_time - timedelta(hours=hours)
        
        suspicious_findings = []
        total_events = 0
        
        try:
            # Query CloudTrail with pagination
            paginator = self.cloudtrail.get_paginator('lookup_events')
            page_iterator = paginator.paginate(
                StartTime=start_time,
                EndTime=end_time
            )
            
            print("Scanning CloudTrail logs...\n")
            
            for page in page_iterator:
                events = page.get('Events', [])
                total_events += len(events)
                
                # Analyze each event
                for event in events:
                    event_name = event.get('EventName', '')
                    
                    if event_name in self.suspicious_events:
                        finding = self._create_finding(event)
                        suspicious_findings.append(finding)
                        
                        # Real-time alert
                        print(f"⚠️  SECURITY ALERT")
                        print(f"   Event: {event_name}")
                        print(f"   User: {event.get('Username', 'Unknown')}")
                        print(f"   Source IP: {event.get('SourceIPAddress', 'Unknown')}")
                        print(f"   Time: {event.get('EventTime')}")
                        print(f"   Status: {event.get('ErrorCode', 'Success')}")
                        print()
            
            print(f"{'='*70}")
            print(f"📊 Analysis Summary")
            print(f"{'='*70}")
            print(f"Total events scanned: {total_events}")
            print(f"Suspicious events found: {len(suspicious_findings)}")
            print(f"{'='*70}\n")
            
            return suspicious_findings
            
        except Exception as e:
            print(f"❌ Error analyzing CloudTrail: {str(e)}")
            print(f"   Make sure AWS credentials are configured")
            print(f"   Run: aws configure")
            return []
    
    def _create_finding(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create structured finding from CloudTrail event
        
        Args:
            event: CloudTrail event dictionary
            
        Returns:
            Structured finding dictionary
        """
        return {
            'event_name': event.get('EventName', 'Unknown'),
            'event_time': event.get('EventTime').isoformat() if event.get('EventTime') else None,
            'username': event.get('Username', 'Unknown'),
            'source_ip': event.get('SourceIPAddress', 'Unknown'),
            'user_agent': event.get('UserAgent', 'Unknown'),
            'error_code': event.get('ErrorCode', 'Success'),
            'error_message': event.get('ErrorMessage', ''),
            'aws_region': event.get('AwsRegion', 'Unknown'),
            'event_id': event.get('EventId', 'Unknown'),
            'resources': event.get('Resources', [])
        }
    
    def detect_failed_logins(self, hours: int = 24, threshold: int = 3) -> List[Dict[str, Any]]:
        """
        Detect multiple failed console login attempts (brute force detection)
        
        Args:
            hours: Hours to look back
            threshold: Number of failures to trigger alert
            
        Returns:
            List of users with excessive failed logins
        """
        print(f"\n{'='*70}")
        print(f"🔐 Failed Login Detection")
        print(f"{'='*70}")
        print(f"Threshold: {threshold} attempts")
        print(f"Time window: Last {hours} hours")
        print(f"{'='*70}\n")
        
        end_time = datetime.now()
        start_time = end_time - timedelta(hours=hours)
        
        failed_logins = {}
        
        try:
            paginator = self.cloudtrail.get_paginator('lookup_events')
            page_iterator = paginator.paginate(
                StartTime=start_time,
                EndTime=end_time,
                LookupAttributes=[
                    {'AttributeKey': 'EventName', 'AttributeValue': 'ConsoleLogin'}
                ]
            )
            
            for page in page_iterator:
                for event in page.get('Events', []):
                    error_code = event.get('ErrorCode')
                    
                    if error_code == 'Failed authentication':
                        username = event.get('Username', 'Unknown')
                        source_ip = event.get('SourceIPAddress', 'Unknown')
                        
                        key = f"{username}_{source_ip}"
                        if key not in failed_logins:
                            failed_logins[key] = {
                                'username': username,
                                'source_ip': source_ip,
                                'attempts': 0,
                                'first_attempt': event.get('EventTime'),
                                'last_attempt': event.get('EventTime')
                            }
                        
                        failed_logins[key]['attempts'] += 1
                        failed_logins[key]['last_attempt'] = event.get('EventTime')
            
            # Filter by threshold
            alerts = [
                details for details in failed_logins.values()
                if details['attempts'] >= threshold
            ]
            
            if alerts:
                print(f"🚨 BRUTE FORCE ATTEMPTS DETECTED\n")
                for alert in alerts:
                    print(f"   User: {alert['username']}")
                    print(f"   Source IP: {alert['source_ip']}")
                    print(f"   Failed Attempts: {alert['attempts']}")
                    print(f"   First Attempt: {alert['first_attempt']}")
                    print(f"   Last Attempt: {alert['last_attempt']}")
                    print()
            else:
                print(f"✅ No suspicious login patterns detected")
            
            print(f"{'='*70}\n")
            return alerts
            
        except Exception as e:
            print(f"❌ Error detecting failed logins: {str(e)}")
            return []
    
    def generate_report(self, findings: List[Dict[str, Any]]) -> str:
        """
        Generate formatted security report
        
        Args:
            findings: List of security findings
            
        Returns:
            Formatted report string
        """
        report = f"""
╔══════════════════════════════════════════════════════════════════╗
║           CloudTrail Security Analysis Report                    ║
╚══════════════════════════════════════════════════════════════════╝

Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Region: {self.region}
Analysis Period: Last 24 hours

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
EXECUTIVE SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Total Suspicious Events: {len(findings)}
Monitored Event Types: {len(self.suspicious_events)}

"""
        
        if findings:
            # Group by event type
            events_by_type = {}
            for finding in findings:
                event_type = finding['event_name']
                if event_type not in events_by_type:
                    events_by_type[event_type] = []
                events_by_type[event_type].append(finding)
            
            report += "Event Type Breakdown:\n"
            for event_type, events in sorted(events_by_type.items(), 
                                            key=lambda x: len(x[1]), 
                                            reverse=True):
                report += f"  • {event_type}: {len(events)} occurrence(s)\n"
            
            report += "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            report += "DETAILED FINDINGS\n"
            report += "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
            
            for i, finding in enumerate(findings, 1):
                report += f"{i}. {finding['event_name']}\n"
                report += f"   User: {finding['username']}\n"
                report += f"   Source IP: {finding['source_ip']}\n"
                report += f"   Time: {finding['event_time']}\n"
                report += f"   Status: {finding['error_code']}\n"
                report += f"   Region: {finding['aws_region']}\n"
                if finding.get('error_message'):
                    report += f"   Error: {finding['error_message']}\n"
                report += "   " + "─" * 60 + "\n\n"
        else:
            report += "✅ No suspicious activity detected during the analysis period.\n\n"
        
        report += "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        report += "SECURITY RECOMMENDATIONS\n"
        report += "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
        
        if findings:
            report += "1. Review all flagged events for legitimacy\n"
            report += "2. Investigate events with error codes or failures\n"
            report += "3. Verify user actions with team members\n"
            report += "4. Consider enabling MFA for users with suspicious activity\n"
            report += "5. Review IAM policies for least-privilege compliance\n"
            report += "6. Enable GuardDuty for additional threat detection\n"
        else:
            report += "1. Continue monitoring CloudTrail logs regularly\n"
            report += "2. Review security policies and access controls\n"
            report += "3. Ensure GuardDuty is enabled for threat detection\n"
            report += "4. Consider implementing automated alerting\n"
            report += "5. Perform periodic security audits\n"
        
        report += "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        
        return report


def main():
    """Main execution function"""
    print("\n" + "="*70)
    print("🚀 SecureCloud CloudTrail Analyzer")
    print("   Enterprise Security Monitoring Platform")
    print("="*70)
    
    # Initialize analyzer
    analyzer = CloudTrailAnalyzer()
    
    try:
        # Phase 1: Analyze recent events
        findings = analyzer.analyze_recent_events(hours=24)
        
        # Phase 2: Detect failed logins
        failed_logins = analyzer.detect_failed_logins(hours=24, threshold=3)
        
        # Phase 3: Generate report
        if findings or failed_logins:
            report = analyzer.generate_report(findings)
            print("\n" + report)
            
            # Save report
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"cloudtrail_security_report_{timestamp}.txt"
            
            with open(filename, 'w') as f:
                f.write(report)
            
            print(f"📄 Report saved to: {filename}")
        else:
            print("\n✅ Security Status: All Clear")
            print("   No suspicious activity detected in the last 24 hours\n")
        
        print("="*70)
        print("Analysis complete!")
        print("="*70 + "\n")
        
    except Exception as e:
        print(f"\n❌ Fatal Error: {str(e)}")
        print("\nTroubleshooting:")
        print("1. Ensure AWS credentials are configured: aws configure")
        print("2. Verify CloudTrail is enabled in your AWS account")
        print("3. Check IAM permissions for CloudTrail access")
        print()


if __name__ == "__main__":
    main()
