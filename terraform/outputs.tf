output "vpc_id" {
  description = "ID of the main VPC"
  value       = aws_vpc.main.id
}

output "subnet1_id" {
  description = "ID of public subnet 1 (10.0.0.0/24)"
  value       = aws_subnet.sub1.id
}

output "subnet2_id" {
  description = "ID of public subnet 2 (10.0.1.0/24)"
  value       = aws_subnet.sub2.id
}

output "ec2_1_public_ip" {
  description = "Public IP address of EC2 instance 1"
  value       = aws_instance.ec2_1.public_ip
}

output "ec2_2_public_ip" {
  description = "Public IP address of EC2 instance 2"
  value       = aws_instance.ec2_2.public_ip
}

output "alb_dns_name" {
  description = "DNS name of the Application Load Balancer"
  value       = aws_lb.main_alb.dns_name
}

output "s3_bucket_name" {
  description = "Name of the S3 data bucket"
  value       = aws_s3_bucket.data_bucket.bucket
}

output "ec2_sg_id" {
  description = "ID of the EC2 security group"
  value       = aws_security_group.ec2_sg.id
}

output "alb_sg_id" {
  description = "ID of the ALB security group"
  value       = aws_security_group.alb_sg.id
}
