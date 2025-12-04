# Terraform Infrastructure Configuration
# This file contains intentional security issues for demo purposes

provider "aws" {
  region = "us-east-1"
}

# ============================================
# CRITICAL ISSUES - Will BLOCK the PR
# ============================================

# CRITICAL: Public S3 bucket
resource "aws_s3_bucket" "data_bucket" {
  bucket = "company-sensitive-data"
  acl    = "public-read"
  
  tags = {
    Environment = "production"
  }
}

# CRITICAL: Overly permissive IAM policy (wildcard)
resource "aws_iam_policy" "admin_policy" {
  name        = "admin-full-access"
  description = "Full admin access"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}

# CRITICAL: Hardcoded database password
resource "aws_db_instance" "production_db" {
  identifier     = "prod-database"
  engine         = "mysql"
  engine_version = "8.0"
  instance_class = "db.t3.medium"
  
  username = "admin"
  password = "ProductionPassword123!"  # CRITICAL: Hardcoded secret
  
  allocated_storage = 100
  storage_type      = "gp2"
}


# ============================================
# HIGH ISSUES - Will BLOCK the PR
# ============================================

# HIGH: Security group open to the world
resource "aws_security_group" "web_sg" {
  name        = "web-server-sg"
  description = "Security group for web servers"
  vpc_id      = aws_vpc.main.id

  # HIGH: SSH open to 0.0.0.0/0
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "SSH access"
  }

  # HIGH: All ports open to the world
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "All TCP"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# HIGH: Unencrypted EBS volume
resource "aws_ebs_volume" "data_volume" {
  availability_zone = "us-east-1a"
  size              = 100
  encrypted         = false  # HIGH: Storage not encrypted
  
  tags = {
    Name = "data-volume"
  }
}


# ============================================
# MEDIUM ISSUES - Will show as SUGGESTIONS
# ============================================

# MEDIUM: S3 bucket without logging
resource "aws_s3_bucket" "logs_bucket" {
  bucket = "company-logs"
  acl    = "private"
  
  logging {
    # MEDIUM: Empty logging configuration
  }
}

# MEDIUM: HTTP listener instead of HTTPS
resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.main.arn
  port              = 80
  protocol          = "HTTP"  # MEDIUM: Should use HTTPS
  
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.main.arn
  }
}


# Supporting resources
resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
  
  tags = {
    Name = "main-vpc"
  }
}

resource "aws_lb" "main" {
  name               = "main-lb"
  internal           = false
  load_balancer_type = "application"
  
  tags = {
    Environment = "production"
  }
}

resource "aws_lb_target_group" "main" {
  name     = "main-tg"
  port     = 80
  protocol = "HTTP"
  vpc_id   = aws_vpc.main.id
}
