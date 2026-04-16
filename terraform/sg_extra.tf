# ──────────────────────────────────────────────────────────────────────────────
# sg_extra.tf – Additional Security Groups
#
# Arsitektur yang benar memisahkan SG antara ALB, EC2, Bastion, dan DB.
# File ini mendefinisikan SG tambahan yang lebih granular dibandingkan
# webSg di main.tf yang dipakai bersama oleh ALB dan EC2.
# ──────────────────────────────────────────────────────────────────────────────

# ALB Security Group – hanya menerima HTTP dan HTTPS dari internet
resource "aws_security_group" "albSg" {
  name        = "alb-sg"
  description = "Security group for Application Load Balancer only"
  vpc_id      = aws_vpc.myvpc.id

  ingress {
    description = "HTTP from internet"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTPS from internet"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "alb-sg"
  }
}

# Bastion Security Group – SSH hanya dari IP terpercaya (bukan 0.0.0.0/0)
# Menggunakan 203.0.113.0/24 (TEST-NET-3, RFC 5737) sebagai contoh IP korporat
resource "aws_security_group" "bastionSg" {
  name        = "bastion-sg"
  description = "Security group for Bastion host – SSH restricted to trusted IP"
  vpc_id      = aws_vpc.myvpc.id

  ingress {
    description = "SSH from trusted corporate IP"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["203.0.113.0/24"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "bastion-sg"
  }
}

# DB Security Group – MySQL hanya dari dalam VPC
# Tidak boleh ada ingress dari internet (0.0.0.0/0 dilarang)
resource "aws_security_group" "dbSg" {
  name        = "db-sg"
  description = "Security group for DB instances – MySQL restricted to VPC CIDR"
  vpc_id      = aws_vpc.myvpc.id

  ingress {
    description = "MySQL from VPC internal only"
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "db-sg"
  }
}
