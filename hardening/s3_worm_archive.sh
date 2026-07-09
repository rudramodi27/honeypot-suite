#!/bin/sh
# =====================================================================
# hardening/s3_worm_archive.sh
# Sets up an S3 bucket with Object Lock in COMPLIANCE mode for
# write-once-read-many honeypot log archival — logs written here
# cannot be deleted or overwritten by ANYONE, including the AWS root
# account, until the retention period expires.
#
# NOT executed against a real AWS account in this exercise (no AWS
# credentials available in this build environment) — `aws` CLI command
# syntax reviewed for correctness against current AWS CLI v2 docs, not
# run live. Object Lock can ONLY be enabled at bucket CREATION time —
# if you have an existing bucket without it, you must create a new one
# and migrate, you cannot retrofit Object Lock onto it.
# =====================================================================
set -eu

BUCKET="${BUCKET:-honeypot-log-archive-worm}"
REGION="${REGION:-us-east-1}"
RETENTION_DAYS="${RETENTION_DAYS:-365}"     # COMPLIANCE mode: not reducible by anyone once set

echo "# 1. Create the bucket WITH Object Lock enabled at creation time"
echo "aws s3api create-bucket \\"
echo "    --bucket \"$BUCKET\" \\"
echo "    --region \"$REGION\" \\"
echo "    --object-lock-enabled-for-bucket"

echo ""
echo "# 2. Set the DEFAULT retention policy — COMPLIANCE mode means even"
echo "#    the bucket owner / root account cannot delete or shorten this"
echo "#    before it expires (GOVERNANCE mode can be overridden by a"
echo "#    user with s3:BypassGovernanceRetention — only use COMPLIANCE"
echo "#    if you're certain about the retention window)."
cat << EOF
aws s3api put-object-lock-configuration \\
    --bucket "$BUCKET" \\
    --object-lock-configuration '{
        "ObjectLockEnabled": "Enabled",
        "Rule": {
            "DefaultRetention": {
                "Mode": "COMPLIANCE",
                "Days": $RETENTION_DAYS
            }
        }
    }'
EOF

echo ""
echo "# 3. Block all public access (Object Lock protects against"
echo "#    deletion, not against exposure — both are needed)"
cat << EOF
aws s3api put-public-access-block \\
    --bucket "$BUCKET" \\
    --public-access-block-configuration \\
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
EOF

echo ""
echo "# 4. Enforce SSE-KMS encryption at rest by default"
cat << EOF
aws s3api put-bucket-encryption \\
    --bucket "$BUCKET" \\
    --server-side-encryption-configuration '{
        "Rules": [{
            "ApplyServerSideEncryptionByDefault": {
                "SSEAlgorithm": "aws:kms",
                "KMSMasterKeyID": "alias/honeypot-log-archive"
            }
        }]
    }'
EOF

echo ""
echo "# 5. Bucket policy: deny delete / retention-bypass attempts outright"
echo "#    (defense in depth on top of Object Lock itself — cheap"
echo "#    insurance against IAM misconfiguration elsewhere)."
cat << EOF
aws s3api put-bucket-policy \\
    --bucket "$BUCKET" \\
    --policy '{
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "DenyDeleteAndRetentionBypass",
            "Effect": "Deny",
            "Principal": "*",
            "Action": [
                "s3:DeleteObject",
                "s3:DeleteObjectVersion",
                "s3:BypassGovernanceRetention",
                "s3:PutObjectRetention"
            ],
            "Resource": "arn:aws:s3:::'"$BUCKET"'/*"
        }]
    }'
EOF

echo ""
echo "# 6. Verify the configuration"
echo "aws s3api get-object-lock-configuration --bucket \"$BUCKET\""
echo "aws s3api get-bucket-encryption --bucket \"$BUCKET\""

echo ""
echo "# 7. Test write (should succeed — writes are still allowed,"
echo "#    only deletion/retention-reduction is blocked)"
echo "echo '{\"test\": true}' | aws s3 cp - \"s3://$BUCKET/honeypot-events/test.json\""

echo ""
echo "# 8. Test delete (SHOULD FAIL with AccessDenied — run this as"
echo "#    part of any deployment validation checklist, it's the actual"
echo "#    proof the WORM policy works, not just configured)"
echo "aws s3 rm \"s3://$BUCKET/honeypot-events/test.json\"   # expect: AccessDenied"
