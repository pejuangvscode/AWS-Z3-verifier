# ──────────────────────────────────────────────────────────────────────────────
# extra_instances.tf – Bastion Host, App Server, S3 Logs Bucket
# ──────────────────────────────────────────────────────────────────────────────

# Bastion Host – jump server di public subnet dengan SG terbatas
# SSH hanya dari IP korporat (203.0.113.0/24), bukan dari 0.0.0.0/0
resource "aws_instance" "bastion" {
  ami                    = "ami-0261755bbcb8c4a84"
  instance_type          = "t2.micro"
  vpc_security_group_ids = [aws_security_group.bastionSg.id]
  subnet_id              = aws_subnet.sub1.id

  tags = {
    Name = "bastion-host"
  }
}

# App Server – di private subnet, tidak bisa diakses langsung dari internet
# Hanya bisa diakses dari VPC internal (via Bastion atau ALB)
resource "aws_instance" "appserver" {
  ami                    = "ami-0261755bbcb8c4a84"
  instance_type          = "t2.micro"
  vpc_security_group_ids = [aws_security_group.webSg.id]
  subnet_id              = aws_subnet.sub3.id

  tags = {
    Name = "app-server"
  }
}

# DB Server – di private subnet, port 3306 hanya dari VPC
resource "aws_instance" "dbserver" {
  ami                    = "ami-0261755bbcb8c4a84"
  instance_type          = "t2.micro"
  vpc_security_group_ids = [aws_security_group.dbSg.id]
  subnet_id              = aws_subnet.sub4.id

  tags = {
    Name = "db-server"
  }
}

# S3 Bucket untuk access logs ALB
resource "aws_s3_bucket" "logs" {
  bucket = "my-access-logs-bucket-demo"

  tags = {
    Name = "logs-bucket"
  }
}

# S3 Bucket untuk backup data
resource "aws_s3_bucket" "backup" {
  bucket = "my-backup-bucket-demo"

  tags = {
    Name = "backup-bucket"
  }
}
