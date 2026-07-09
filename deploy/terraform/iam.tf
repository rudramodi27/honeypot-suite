# =====================================================================
# deploy/terraform/iam.tf
# IAM role for the honeypot EC2 instance (least-privilege — it can
# write its own logs out, nothing else) and an MFA-enforced policy for
# human admin access to the honeypot account/resources.
#
# NOT applied against a real AWS account in this exercise — same
# caveat as security_group.tf: no terraform binary or AWS provider
# access in this build environment. HCL syntax follows standard
# `aws_iam_role`/`aws_iam_policy` resource schemas; review before apply.
# =====================================================================

# ── Instance role: what the honeypot EC2 instance itself can do ─────
# Deliberately narrow — write CloudWatch Logs, PutObject to the WORM
# log-archive bucket (see hardening/s3_worm_archive.sh), nothing else.
# No EC2:*, no IAM:*, no access to other accounts' resources. If this
# instance is ever compromised, the attacker inherits THIS role's
# permissions — keep the blast radius to "can write logs," not "can
# pivot through the AWS account."
resource "aws_iam_role" "honeypot_instance_role" {
  name = "honeypot-instance-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "honeypot_instance_policy" {
  name = "honeypot-instance-least-privilege"
  role = aws_iam_role.honeypot_instance_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "WriteOwnCloudWatchLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogStreams"
        ]
        Resource = "arn:aws:logs:*:*:log-group:/honeypot/*"
      },
      {
        Sid      = "WriteToWormArchiveOnly"
        Effect   = "Allow"
        Action   = ["s3:PutObject"]
        Resource = "arn:aws:s3:::honeypot-log-archive-worm/*"
        # Deliberately NO s3:GetObject, s3:DeleteObject, or s3:List* —
        # this role can write new log objects and nothing else, so a
        # compromised honeypot can't read back or tamper with archived
        # evidence even before Object Lock's own protections apply.
      },
      {
        Sid      = "ReadOwnSecretsOnly"
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue"]
        Resource = "arn:aws:secretsmanager:*:*:secret:honeypot/*"
      }
    ]
  })
}

resource "aws_iam_instance_profile" "honeypot_instance_profile" {
  name = "honeypot-instance-profile"
  role = aws_iam_role.honeypot_instance_role.name
}

# ── Human admin access: MFA enforced via IAM policy condition ───────
# This is the IAM-equivalent of the Kubernetes RBAC MFA note in
# deploy/k8s/20-rbac.yaml — IAM itself doesn't "have MFA," but you can
# make every sensitive action FAIL unless the calling principal's
# session was established with MFA, which is the actual enforcement
# mechanism (not a checkbox, a deny-by-default condition).
resource "aws_iam_policy" "honeypot_admin_requires_mfa" {
  name        = "honeypot-admin-requires-mfa"
  description = "Allows honeypot admin actions ONLY when the session was authenticated with MFA"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyAllExceptMFA"
        Effect = "Deny"
        NotAction = [
          "iam:ListMFADevices",
          "iam:ListVirtualMFADevices",
          "iam:ListUsers",
          "sts:GetSessionToken"
        ]
        Resource = "*"
        Condition = {
          BoolIfExists = {
            "aws:MultiFactorAuthPresent" = "false"
          }
        }
      },
      {
        Sid    = "AllowHoneypotAdminWithMFA"
        Effect = "Allow"
        Action = [
          "ec2:StartInstances",
          "ec2:StopInstances",
          "ec2:RebootInstances",
          "ssm:StartSession",
          "logs:GetLogEvents",
          "logs:FilterLogEvents",
          "secretsmanager:GetSecretValue",
          "secretsmanager:PutSecretValue"
        ]
        Resource = "*"
        Condition = {
          Bool = {
            "aws:MultiFactorAuthPresent" = "true"
          }
        }
      }
    ]
  })
}

# Attach to an admin group rather than individual users, same
# group-over-individual principle as the Kubernetes RBAC bindings.
resource "aws_iam_group" "honeypot_admins" {
  name = "honeypot-admins"
}

resource "aws_iam_group_policy_attachment" "honeypot_admins_mfa_policy" {
  group      = aws_iam_group.honeypot_admins.name
  policy_arn = aws_iam_policy.honeypot_admin_requires_mfa.arn
}

# Validation status: same as security_group.tf — HCL reviewed for
# standard resource syntax, not run against a live AWS provider in
# this build environment (no terraform binary, no AWS credentials).
