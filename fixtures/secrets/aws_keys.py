# thorn test fixture: SEC001, SEC002
# Contains fake AWS credentials for scanner testing only

import boto3

# This is a real-looking but invalid AWS key pair
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# This line should NOT match (not a key pattern)
region = "us-east-1"
bucket_name = "my-test-bucket"

client = boto3.client(
    "s3",
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
)
