resource "aws_key_pair" "deployer" {
  key_name   = "deployer-key"
  public_key = file("~/.ssh/glove.pub")
}

resource "aws_instance" "enclave" {
  ami                  = data.aws_ami.al2023.id
  instance_type        = "c5.2xlarge"
  iam_instance_profile = aws_iam_instance_profile.enclave.name
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
  vpc_security_group_ids = [
    aws_security_group.external-ssh.id,
    aws_security_group.internal.id,
  ]
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

resource "aws_security_group" "internal" {
  name        = "enclave-internal-traffic"
  description = "allows internal traffic (from lb)"
}

resource "aws_security_group_rule" "internal_http" {
  type              = "ingress"
  protocol          = "tcp"
  from_port         = 8080
  to_port           = 8080
  cidr_blocks       = [data.aws_vpc.default.cidr_block]
  description       = "HTTP web traffic"
  security_group_id = aws_security_group.internal.id
}

resource "aws_security_group_rule" "internal_all" {
  type              = "egress"
  protocol          = "-1"
  from_port         = 0
  to_port           = 0
  cidr_blocks       = [data.aws_vpc.default.cidr_block]
  description       = "All egress"
  security_group_id = aws_security_group.internal.id
}

resource "aws_iam_role" "enclave" {
  name                 = "enclave"
  assume_role_policy   = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      },
    ]
  })
  managed_policy_arns = [data.aws_iam_policy.dynamodb_full.arn]
  description          = "Give EC2 instances access to DynamoDB"
  force_detach_policies = true
}


resource "aws_iam_instance_profile" "enclave" {
  name = "enclave"
  role = aws_iam_role.enclave.name
}
