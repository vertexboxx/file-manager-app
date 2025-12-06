# s3_utils.py
import os
import boto3
from botocore.exceptions import ClientError

AWS_REGION = os.environ.get("AWS_REGION")
AWS_ACCESS_KEY_ID = os.environ.get("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY")
S3_BUCKET = os.environ.get("S3_BUCKET")

# Create S3 client (uses provided env vars)
_s3 = boto3.client(
    "s3",
    region_name=AWS_REGION,
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
)

def upload_to_s3(local_path, object_key):
    """Upload a local file to S3. Returns True on success, False on failure."""
    try:
        _s3.upload_file(local_path, S3_BUCKET, object_key)
        return True
    except ClientError as e:
        # Let caller log/raise as needed
        print("S3 upload error:", e)
        return False

def get_s3_url(object_key):
    """Return a simple public S3 URL for the object (or None if no key)."""
    if not object_key:
        return None
    bucket = S3_BUCKET
    region = AWS_REGION or "ap-south-1"
    return f"https://{bucket}.s3.{region}.amazonaws.com/{object_key}"

def download_from_s3(object_key, dest_path):
    """Download an object from S3 to dest_path. Returns True on success."""
    try:
        _s3.download_file(S3_BUCKET, object_key, dest_path)
        return True
    except ClientError as e:
        print("S3 download error:", e)
        return False

def generate_s3_presigned_url(object_key, expires_in=3600):
    """Generate a presigned GET URL for an object."""
    try:
        return _s3.generate_presigned_url(
            "get_object",
            Params={"Bucket": S3_BUCKET, "Key": object_key},
            ExpiresIn=expires_in,
        )
    except ClientError as e:
        print("S3 presign error:", e)
        return None
