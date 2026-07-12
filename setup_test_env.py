"""
Day 1: Provision a small AWS test environment with DELIBERATE misconfigurations,
so the scanners built in Week 1 have real findings to detect.

Run this only against a personal/free-tier AWS account you own.
Never run this against a production or employer/client account.
"""

import boto3
import json
import time
from dotenv import load_dotenv

load_dotenv("config/.env")

REGION = "ap-south-1"
BUCKET_NAME = f"sentry-test-bucket-{int(time.time())}"

iam = boto3.client("iam", region_name=REGION)
s3 = boto3.client("s3", region_name=REGION)
ec2 = boto3.client("ec2", region_name=REGION)


def create_overprivileged_iam_user():
    print("[IAM] Creating a deliberately overprivileged user...")
    user_name = "sentry-test-overprivileged"
    iam.create_user(UserName=user_name)

    wildcard_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
    }
    iam.put_user_policy(
        UserName=user_name,
        PolicyName="sentry-test-wildcard-policy",
        PolicyDocument=json.dumps(wildcard_policy),
    )
    print(f"[IAM] Created user '{user_name}' with a wildcard (*:*) inline policy.")


def create_public_s3_bucket():
    print(f"[S3] Creating bucket {BUCKET_NAME} with public access...")
    s3.create_bucket(
        Bucket=BUCKET_NAME,
        CreateBucketConfiguration={"LocationConstraint": REGION},
    )
    # Disable block-public-access (deliberately insecure, for test detection only)
    s3.put_public_access_block(
        Bucket=BUCKET_NAME,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": False,
            "IgnorePublicAcls": False,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": False,
        },
    )
    public_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:GetObject",
            "Resource": f"arn:aws:s3:::{BUCKET_NAME}/*",
        }],
    }
    s3.put_bucket_policy(Bucket=BUCKET_NAME, Policy=json.dumps(public_policy))
    print(f"[S3] Bucket '{BUCKET_NAME}' is now public.")


def create_open_security_group():
    print("[EC2] Creating a security group open to the world...")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "isDefault", "Values": ["true"]}])
    vpc_id = vpcs["Vpcs"][0]["VpcId"]

    sg = ec2.create_security_group(
        GroupName="sentry-test-open-sg",
        Description="Deliberately open SG for SENTRY scanner testing",
        VpcId=vpc_id,
    )
    sg_id = sg["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[{
            "IpProtocol": "tcp",
            "FromPort": 22,
            "ToPort": 22,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        }],
    )
    print(f"[EC2] Security group '{sg_id}' has SSH (22) open to 0.0.0.0/0.")


if __name__ == "__main__":
    print("=== SENTRY Day 1: Provisioning test environment ===")
    print("WARNING: this creates real (free-tier) AWS resources with intentional")
    print("security holes. Only run this against your own test/sandbox account.\n")

    create_overprivileged_iam_user()
    create_public_s3_bucket()
    create_open_security_group()

    print("\nDone. These resources are now sitting in your account as scanner targets.")
    print("Next (Day 2): build iam_scanner.py to detect the wildcard policy above.")
