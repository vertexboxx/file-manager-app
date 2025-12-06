import boto3, os
from botocore.exceptions import NoCredentialsError

AWS_ACCESS_KEY_ID = os.environ.get("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY")
AWS_REGION = os.environ.get("AWS_REGION")
S3_BUCKET = os.environ.get("S3_BUCKET")

s3_client = boto3.client(
    "s3",
    region_name=AWS_REGION,
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY
)

def upload_to_s3(file_path, object_name):
    try:
        s3_client.upload_file(file_path, S3_BUCKET, object_name)
        return True
    except Exception as e:
        print("S3 upload error:", e)
        return False

def download_from_s3(object_name, dest_path):
    try:
        s3_client.download_file(S3_BUCKET, object_name, dest_path)
        return True
    except Exception as e:
        print("S3 download error:", e)
        return False

def generate_s3_url(object_name):
    return f"https://{S3_BUCKET}.s3.{AWS_REGION}.amazonaws.com/{object_name}"
