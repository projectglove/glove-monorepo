resource "aws_lb" "enclave" {
  name               = "enclave"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.lb_enclave.id]
  subnets            = [for subnet in data.aws_subnets.default : subnet.id]

  enable_deletion_protection = true

  /*  access_logs {
    bucket  = aws_s3_bucket.lb_logs.id
    prefix  = "test-lb"
    enabled = true
  }
*/
}

resource "aws_security_group" "lb_enclave" {
  name        = "enclave-lb"
  description = "allows external HTTPS access"
  vpc_id      = data.aws_vpc.default.id
}

resource "aws_vpc_security_group_ingress_rule" "http" {
  security_group_id = aws_security_group.lb_enclave
  from_port         = 80
  to_port           = 80
  ip_protocol       = "tcp"
  description       = "HTTP web traffic"
  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_vpc_security_group_ingress_rule" "https" {
  security_group_id = aws_security_group.lb_enclave
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
  description       = "HTTPS web traffic"
  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_vpc_security_group_egress_rule" "all" {
  security_group_id = aws_security_group.lb_enclave
  from_port         = 0
  to_port           = 0
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"
}
