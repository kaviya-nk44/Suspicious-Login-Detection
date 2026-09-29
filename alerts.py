import os
import sys
import boto3

def send_admin_alert(username, ip_address, timestamp, risk_level, reason="High Risk Suspicious Login Pattern"):
    """
    Real-Time Administrator Alert System (Phase 7):
    - Terminal Output: Prints urgent alert with flush=True.
    - AWS SNS Hook: Dispatches notification to AWS SNS Topic if AWS_SNS_TOPIC_ARN is configured,
      or operates seamlessly in local fallback/mock mode.
    """
    urgent_log = (
        f"[URGENT ALERT] High Risk Login Detected! "
        f"User: {username} | IP: {ip_address} | Time: {timestamp} | Reason: {reason}"
    )
    
    # 1. Immediate Terminal Log
    print(urgent_log, flush=True)
    sys.stdout.flush()
    sys.stderr.flush()

    # 2. AWS SNS Production Hook with Fallback
    sns_topic_arn = os.environ.get('AWS_SNS_TOPIC_ARN')
    if sns_topic_arn:
        try:
            region = os.environ.get('AWS_REGION', 'us-east-1')
            sns_client = boto3.client('sns', region_name=region)
            sns_client.publish(
                TopicArn=sns_topic_arn,
                Subject=f"SECURITY ALERT: High Risk Login by {username}",
                Message=urgent_log
            )
            print(f"[AWS SNS DISPATCHED] Alert sent to topic {sns_topic_arn}", flush=True)
        except Exception as e:
            print(f"[AWS SNS FALLBACK] Failed to dispatch SNS notification: {e}", flush=True)
    else:
        print(f"[AWS SNS HOOK] (Mock Mode) Topic ARN not specified. Alert logged locally.", flush=True)
