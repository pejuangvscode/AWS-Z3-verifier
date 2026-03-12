variable "aws_region" {
  description = "AWS region to deploy resources into"
  type        = string
  default     = "us-east-1"
}

variable "ami_id" {
  description = "AMI ID to use for EC2 instances (Amazon Linux 2, us-east-1)"
  type        = string
  default     = "ami-0c55b159cbfafe1f0"
}

variable "s3_bucket_name" {
  description = "Globally unique name for the S3 data bucket"
  type        = string
  default     = "my-data-bucket-secure-demo"
}
