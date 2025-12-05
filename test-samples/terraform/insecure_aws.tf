# Insecure AWS Infrastructure
# 
# TEST SCENARIO: AI should detect IaC misconfigurations
# - Open security groups
# - Unencrypted storage
# - Overly permissive IAM
# - Public resources
# - Missing logging

provider "aws" {
  region = "us-east-1"
}

# VULNERABILITY: Public S3 bucket (CWE-284, SCF-NET-01)
# AI CONTEXT TEST: Should detect public ACL as critical
resource "aws_s3_bucket" "data_bucket" {
  bucket = "company-sensitive-data"
  acl    = "public-read"  # CRITICAL: Public access to sensitive data!
  
  # Missing: encryption configuration
  # Missing: versioning
  # Missing: logging
}

# VULNERABILITY: Unencrypted S3 bucket (SCF-CRY-01)
resource "aws_s3_bucket" "backup_bucket" {
  bucket = "company-backups"
  
  # CRITICAL: No server-side encryption configured
  # Should have: server_side_encryption_configuration block
}

# VULNERABILITY: Open security group (CWE-284, SCF-NET-01)
# AI CONTEXT TEST: Should detect 0.0.0.0/0 as critical for SSH/DB ports
resource "aws_security_group" "web_sg" {
  name        = "web-server-sg"
  description = "Security group for web servers"
  vpc_id      = "vpc-12345678"

  # CRITICAL: SSH open to the world
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # Anyone can SSH!
  }

  # CRITICAL: Database port open to the world
  ingress {
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # Database exposed!
  }

  # CRITICAL: All egress allowed
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# VULNERABILITY: Overly permissive IAM policy (SCF-IAC-01)
# AI CONTEXT TEST: Should detect wildcard permissions as high risk
resource "aws_iam_policy" "admin_policy" {
  name        = "super-admin-policy"
  description = "Policy with excessive permissions"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"           # CRITICAL: Full admin access!
        Resource = "*"           # CRITICAL: All resources!
      }
    ]
  })
}

# VULNERABILITY: IAM role assumable by anyone (SCF-IAC-01)
resource "aws_iam_role" "lambda_role" {
  name = "lambda-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = "*"          # CRITICAL: Anyone can assume this role!
        Action    = "sts:AssumeRole"
      }
    ]
  })
}

# VULNERABILITY: Unencrypted RDS instance (SCF-CRY-01, PCI-DSS)
resource "aws_db_instance" "main_db" {
  identifier        = "production-database"
  engine            = "mysql"
  instance_class    = "db.t3.medium"
  allocated_storage = 100
  
  username = "admin"
  password = "SuperSecretPassword123!"  # CRITICAL: Hardcoded password!
  
  publicly_accessible = true   # CRITICAL: Database is public!
  storage_encrypted   = false  # CRITICAL: No encryption at rest!
  
  # Missing: backup_retention_period
  # Missing: deletion_protection
  # Missing: enabled_cloudwatch_logs_exports
}

# VULNERABILITY: Missing CloudTrail (SCF-LOG-01)
# AI CONTEXT TEST: Should note absence of audit logging
# No aws_cloudtrail resource defined - compliance violation!

# VULNERABILITY: EBS volume without encryption (SCF-CRY-01)
resource "aws_ebs_volume" "data_volume" {
  availability_zone = "us-east-1a"
  size              = 500
  
  encrypted = false  # CRITICAL: Unencrypted storage!
  
  tags = {
    Name = "production-data"
  }
}
