# =====================================================================
# deploy/terraform/security_group.tf
# AWS equivalent of deploy/iptables/honeypot-egress.sh — deny-all
# outbound from the honeypot security group except to the SIEM
# ingestion endpoint, with explicit inbound rules per honeypot port.
#
# NOT applied against a real AWS account in this exercise — `terraform
# validate` is run locally for syntax correctness only (see validation
# notes at the bottom of this file); review variable defaults, VPC IDs,
# and the SIEM CIDR before `terraform apply` against real infrastructure.
# =====================================================================

variable "vpc_id" {
  description = "VPC the honeypot subnet lives in"
  type        = string
}

variable "siem_cidr" {
  description = "CIDR of your SIEM/log-collector endpoint (the ONLY allowed egress destination)"
  type        = string
  default     = "10.0.0.0/24"     # CHANGE ME before apply
}

variable "siem_port" {
  description = "SIEM ingestion port (Filebeat/Logstash default 5044, Splunk HEC 8088)"
  type        = number
  default     = 5044
}

variable "management_cidr" {
  description = "CIDR allowed to reach the dashboard (5000) and SSH-to-host (22) — your VPN/bastion, NOT 0.0.0.0/0"
  type        = string
}

resource "aws_security_group" "honeypot" {
  name        = "honeypot-segregated-sg"
  description = "Honeypot listeners — deny-all egress except SIEM shipping"
  vpc_id      = var.vpc_id

  tags = {
    Name        = "honeypot-segregated-sg"
    Environment = "honeypot"
    ManagedBy   = "terraform"
  }
}

# ── Inbound: honeypot listener ports, open to the internet (that's the point) ──
resource "aws_security_group_rule" "inbound_ssh_honeypot" {
  type              = "ingress"
  from_port         = 2222
  to_port           = 2222
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.honeypot.id
  description       = "SSH honeypot — intentionally open"
}

resource "aws_security_group_rule" "inbound_http_honeypot" {
  type              = "ingress"
  from_port         = 8080
  to_port           = 8080
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.honeypot.id
  description       = "HTTP honeypot — intentionally open"
}

resource "aws_security_group_rule" "inbound_ftp_honeypot" {
  type              = "ingress"
  from_port         = 2121
  to_port           = 2121
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.honeypot.id
  description       = "FTP honeypot — intentionally open"
}

resource "aws_security_group_rule" "inbound_decoy_ports" {
  for_each          = toset(["3306", "6379", "2525", "8443", "8081", "9200"])
  type              = "ingress"
  from_port         = tonumber(each.value)
  to_port           = tonumber(each.value)
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.honeypot.id
  description       = "Decoy service ${each.value} — intentionally open"
}

# ── Inbound: management plane, restricted to a trusted CIDR only ──
resource "aws_security_group_rule" "inbound_dashboard" {
  type              = "ingress"
  from_port         = 5000
  to_port           = 5000
  protocol          = "tcp"
  cidr_blocks       = [var.management_cidr]
  security_group_id = aws_security_group.honeypot.id
  description       = "Dashboard — restricted to management CIDR, NOT public"
}

resource "aws_security_group_rule" "inbound_ssh_mgmt" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = [var.management_cidr]
  security_group_id = aws_security_group.honeypot.id
  description       = "Host SSH for ops — restricted to management CIDR"
}

# ── Outbound: deny-all by default (no catch-all 0.0.0.0/0 rule),
#    explicit allow only to the SIEM endpoint ────────────────────
resource "aws_security_group_rule" "outbound_siem_only" {
  type              = "egress"
  from_port         = var.siem_port
  to_port           = var.siem_port
  protocol          = "tcp"
  cidr_blocks       = [var.siem_cidr]
  security_group_id = aws_security_group.honeypot.id
  description       = "Outbound to SIEM ingestion endpoint ONLY"
}

# Required for the security group to be valid for instances that need
# DNS resolution of the SIEM hostname; scope to the VPC resolver, not
# the wider internet. Omit entirely if you ship logs by IP literal.
resource "aws_security_group_rule" "outbound_dns_vpc_resolver" {
  type              = "egress"
  from_port         = 53
  to_port           = 53
  protocol          = "udp"
  cidr_blocks       = ["169.254.169.253/32"]   # AWS VPC resolver address, not the open internet
  security_group_id = aws_security_group.honeypot.id
  description       = "DNS — VPC resolver only"
}

# NOTE: there is intentionally no rule allowing port 443/80/any to
# 0.0.0.0/0. If the threat-intel enrichment worker needs VirusTotal/
# AbuseIPDB/OTX access, give IT a separate security group (matching the
# enrichment-worker / egress-allow split in docker-compose.hardened.yml)
# rather than widening this one — keep the honeypot listeners themselves
# on a security group that cannot exfiltrate anything.

output "honeypot_security_group_id" {
  value = aws_security_group.honeypot.id
}

# =====================================================================
# Local validation status for this file: NOT run. This sandboxed build
# environment has no terraform binary and no network path to
# releases.hashicorp.com (egress is allowlisted to pypi/npm/github
# only), so `terraform fmt -check` / `terraform validate` could not be
# executed here. The HCL above follows standard `aws_security_group` +
# `aws_security_group_rule` syntax, but run both commands yourself
# against your AWS provider/backend before `terraform plan` — treat
# this as a reviewed template, not a verified-working file.
# =====================================================================
