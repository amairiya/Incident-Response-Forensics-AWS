import boto3
import json
import datetime

iam = boto3.client('iam')
s3 = boto3.client('s3')

S3_BUCKET = "forensics-bucket"

def lambda_handler(event, context):
    # Extraction du finding
    finding = event['detail']
    user = finding['resource']['accessKeyDetails'][0]['userName']
    key_id = finding['resource']['accessKeyDetails'][0]['accessKeyId']

    #  Désactiver la clé IAM compromise
    iam.update_access_key(
        UserName=user,
        AccessKeyId=key_id,
        Status='Inactive'
    )

    #  Attacher une policy de quarantaine
    quarantine_policy = "arn:aws:iam::aws:policy/ReadOnlyAccess"
    iam.attach_user_policy(
        UserName=user,
        PolicyArn=quarantine_policy
    )

    #  Collecte des preuves forensiques
    timestamp = datetime.datetime.utcnow().isoformat()
    log_data = json.dumps(finding)

    s3.put_object(
        Bucket=S3_BUCKET,
        Key=f"forensics/{user}_{timestamp}.json",
        Body=log_data
    )

    print(f"Automated response executed for user {user}")
