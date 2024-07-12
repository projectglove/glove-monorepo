resource "aws_key_pair" "deployer" {
  key_name   = "deployer-key"
  public_key = file("~/.ssh/id_ed25519.pub")
}

resource "aws_security_group" "external-ssh" {
  name        = "enclave-external-ssh"
  description = "allows external SSH access"
  vpc_id      = data.aws_vpc.default.id
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "TCP"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "enclave" {
  ami           = data.aws_ami.al2023.id
  instance_type = "c5.2xlarge"
  enclave_options {
    enabled = true
  }
  key_name = aws_key_pair.deployer.key_name
  root_block_device {
    encrypted   = true
    volume_size = 100
  }
  tags = {
    Name = "HelloWorld"
  }
  vpc_security_group_ids = [aws_security_group.external-ssh.id]
}
