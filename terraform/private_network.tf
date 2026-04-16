# ──────────────────────────────────────────────────────────────────────────────
# private_network.tf – Private Subnets, NAT Gateway, Private Route Table
#
# Menambahkan lapisan jaringan privat di belakang subnet publik.
# EC2 di private subnet TIDAK bisa diakses langsung dari internet,
# tapi masih bisa keluar ke internet via NAT Gateway.
# ──────────────────────────────────────────────────────────────────────────────

# Private Subnet us-east-1a
resource "aws_subnet" "sub3" {
  vpc_id                  = aws_vpc.myvpc.id
  cidr_block              = "10.0.2.0/24"
  availability_zone       = "us-east-1a"
  map_public_ip_on_launch = false

  tags = {
    Name = "private-sub1"
  }
}

# Private Subnet us-east-1b
resource "aws_subnet" "sub4" {
  vpc_id                  = aws_vpc.myvpc.id
  cidr_block              = "10.0.3.0/24"
  availability_zone       = "us-east-1b"
  map_public_ip_on_launch = false

  tags = {
    Name = "private-sub2"
  }
}

# Elastic IP untuk NAT Gateway
resource "aws_eip" "nat_eip" {
  domain     = "vpc"
  depends_on = [aws_internet_gateway.igw]

  tags = {
    Name = "nat-eip"
  }
}

# NAT Gateway di public subnet sub1
# Private subnet bisa keluar ke internet lewat sini, tapi tidak bisa diakses dari internet
resource "aws_nat_gateway" "natgw" {
  allocation_id = aws_eip.nat_eip.id
  subnet_id     = aws_subnet.sub1.id

  tags = {
    Name = "nat-gw"
  }
}

# Private Route Table – routing keluar via NAT GW (bukan IGW)
# Traffic masuk dari internet TIDAK bisa masuk ke private subnet
resource "aws_route_table" "privateRT" {
  vpc_id = aws_vpc.myvpc.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.natgw.id
  }

  tags = {
    Name = "private-rt"
  }
}

resource "aws_route_table_association" "rta3" {
  subnet_id      = aws_subnet.sub3.id
  route_table_id = aws_route_table.privateRT.id
}

resource "aws_route_table_association" "rta4" {
  subnet_id      = aws_subnet.sub4.id
  route_table_id = aws_route_table.privateRT.id
}
