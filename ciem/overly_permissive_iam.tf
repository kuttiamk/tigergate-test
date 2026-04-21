# =============================================================================
# ciem/overly_permissive_iam.tf – TigerGate CNAPP Test: Cross-Cloud CIEM Misconfigs
# =============================================================================
# PURPOSE: Demonstrates over-privileged IAM identities across AWS.
# Tigergate CIEM analyzes the EFFECTIVE permissions of each identity and flags
# those that violate the Principle of Least Privilege.
#
# CIEM FINDINGS TRIGGERED:
#   CIEM-001: IAM role with Action:* Resource:* (full AWS access)
#   CIEM-002: Lambda execution role with AdministratorAccess
#   CIEM-003: Cross-account trust with Principal:* (no ExternalId)
#   CIEM-004: EC2 instance with iam:PassRole (privilege escalation)
#   CIEM-005: Human user with AdministratorAccess (should use federation)
# =============================================================================

provider "aws" {
  region = "us-east-1"
}

# =============================================================================
# 🔴 POLICY 1: Wildcard Admin Policy (Action:* Resource:*)
# CIEM: "Policy allows all actions on all resources"
# This policy is equivalent to root access on everything
# FIX: Replace with specific actions: ["s3:GetObject", "ec2:DescribeInstances"]
#      and specific resources with ARNs
# =============================================================================
resource "aws_iam_policy" "super_admin" {
  name        = "tigergate-super-admin-policy"
  description = "⚠️ INTENTIONALLY OVER-PERMISSIVE for CIEM testing"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "FullAccess"
        Effect   = "Allow"
        Action   = "*"              # 🔴 CIEM-001: Every AWS API action!
        Resource = "*"              # 🔴 CIEM-001: Every resource in the account!
      },
      {
        Sid    = "CanDisableDefenses"
        Effect = "Allow"
        Action = [
          "cloudtrail:StopLogging",      # 🔴 Can disable audit trail!
          "cloudtrail:DeleteTrail",      # 🔴 Can destroy audit logs!
          "guardduty:DeleteDetector",    # 🔴 Can turn off threat detection!
          "config:DeleteConfigRule",     # 🔴 Can destroy compliance rules!
          "cloudwatch:DeleteAlarms",     # 🔴 Can delete security alarms!
          "iam:DeleteRole",              # 🔴 Can delete IAM roles (incl. security)!
          "iam:DetachRolePolicy",        # 🔴 Can weaken other roles!
        ]
        Resource = "*"
      }
    ]
  })
}

# 🔴 BAD: Human user gets AdministratorAccess directly (not via group, not time-bounded)
resource "aws_iam_user" "admin_user" {
  name = "tigergate-admin-user"
  # BAD: No permission boundary
  # BAD: No MFA enforcement
}

resource "aws_iam_user_policy_attachment" "admin_user" {
  user       = aws_iam_user.admin_user.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"  # 🔴 Full access!
}

# 🔴 BAD: Access key created for human user (should use SSO/federation)
resource "aws_iam_access_key" "admin_user" {
  user = aws_iam_user.admin_user.name
  # Static credentials that never expire!
}


# =============================================================================
# 🔴 POLICY 2: EC2 Role with iam:PassRole → Privilege Escalation
# CIEM: "Role allows iam:PassRole leading to privilege escalation"
# WHY: With iam:PassRole, an attacker on the EC2 can attach ANY policy to ANY role
#      and escalate from limited → admin with just one API call
# =============================================================================
resource "aws_iam_role" "ec2_escalation_role" {
  name = "tigergate-ec2-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "ec2_escalation_policy" {
  name = "ec2-escalation-policy"
  role = aws_iam_role.ec2_escalation_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["iam:PassRole", "iam:AttachRolePolicy", "iam:CreatePolicyVersion"]  # 🔴 Escalation!
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = ["s3:*", "rds:*", "ec2:*", "lambda:*"]  # 🔴 More than needed
        Resource = "*"
      }
    ]
  })
}


# =============================================================================
# 🔴 POLICY 3: Cross-Account Trust with Principal:* (No ExternalId)
# CIEM: "Role trust policy allows any principal from any AWS account"
# If this role has admin access AND has Principal:*, any AWS account (attacker's)
# can call sts:AssumeRole and get full access.
# FIX: Specify exact account ARN + require ExternalId condition
# =============================================================================
resource "aws_iam_role" "cross_account_role" {
  name = "tigergate-cross-account-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { AWS = "*" }    # 🔴 CIEM-003: ANY AWS account can assume this role!
        Action    = ["sts:AssumeRole", "sts:AssumeRoleWithWebIdentity"]
        # BAD: No ExternalId condition — confused deputy attack possible!
        # BAD: No MFA condition
        # BAD: No IP restriction
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "cross_account_admin" {
  role       = aws_iam_role.cross_account_role.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"  # 🔴 Admin via any account!
}


# =============================================================================
# 🔴 POLICY 4: Lambda Execution Role with AdministratorAccess
# CIEM: "Lambda function has excessive IAM permissions"
# WHY BAD: Lambda only needs to write to one DynamoDB table.
#          With AdministratorAccess, a compromised Lambda = full account takeover.
# FIX: Create minimal policy:
#   Action: ["dynamodb:PutItem"], Resource: "arn:aws:dynamodb:us-east-1:*:table/my-table"
# =============================================================================
resource "aws_iam_role" "lambda_admin_role" {
  name = "tigergate-lambda-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_admin" {
  role       = aws_iam_role.lambda_admin_role.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"  # 🔴 CIEM-002: Lambda with admin!
}

# Outputs expose sensitive info
output "access_key_id" {
  value = aws_iam_access_key.admin_user.id
}
output "access_key_secret" {
  value     = aws_iam_access_key.admin_user.secret
  sensitive = false   # 🔴 IAM secret key NOT marked sensitive — exposed in terraform output!
}
