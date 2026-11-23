/*
 * Public bucket with the access logs of the shop.
 */
resource "aws_s3_bucket" "logs" {
  bucket = "shop-access-logs"   # the bucket name
  acl    = "private"
  force_destroy = false
  tags = {
    Owner = "platform"
  }

  lifecycle_rule {
    enabled = true
    // keep logs for a year
    expiration {
      days = 365
    }
  }
  lifecycle_rule {
    enabled = false
  }
}

resource "aws_db_instance" "orders" {
  identifier          = "orders-db"
  engine              = "postgres"
  username            = "orders"
  password            = "Sup3rS3cret!"
  allocated_storage   = 20
  vpc_security_group_ids = [aws_security_group.db.id, "sg-0123"]
  subnet_ids          = ["subnet-a", "subnet-b"]
  kms_key_id          = "arn:aws:kms:eu-west-1:111111111111:key/abc"
  endpoint            = "postgres://orders:hunter2@db.example.local:5432/orders"
  storage_type        = var.storage_type
  name                = "${var.prefix}-orders"
  replica             = local.replica_enabled ? 1 : 0

  dynamic "ingress" {
    for_each = var.ingress_ports
    content {
      from_port = ingress.value
      protocol  = "tcp"
    }
  }
}

data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"]
}

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.1.0"
  cidr    = "10.0.0.0/16"
  api_token = var.api_token
}

provider "aws" {
  region = "eu-west-1"
}

provider "aws" {
  alias  = "us"
  region = "us-east-1"
}
