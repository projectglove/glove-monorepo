// It assumes that the AWS profije is called glove-test
provider "aws" {
  region = "us-east-2"
  profile = "glove-test"
}

data "aws_ami" "al2023" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["al2023-ami-2023*"]
  }
}

resource "aws_instance" "enclave" {
  ami           = data.aws_ami.al2023.id
  instance_type = "c5.2xlarge"
  enclave_options {
    enabled = true
  }
  root_block_device {
    encrypted = true
    volume_size = 100
  }
  tags = {
    Name = "HelloWorld"
  }
}
