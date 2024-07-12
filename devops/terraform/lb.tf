resource "aws_lb" "enclave" {
  name               = "enclave"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.lb_enclave.id]
  subnets            = [for s in data.aws_subnets.default.ids: s]

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

resource "aws_security_group_rule" "http" {
  type              = "ingress"
  protocol          = "tcp"
  from_port         = 80
  to_port           = 80
  cidr_blocks         = ["0.0.0.0/0"]
  description       = "HTTP web traffic"
  security_group_id = aws_security_group.lb_enclave.id
}

resource "aws_security_group_rule" "https" {
  type              = "ingress"
  protocol          = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_blocks         = ["0.0.0.0/0"]
  description       = "HTTPS web traffic"
  security_group_id = aws_security_group.lb_enclave.id
}

resource "aws_security_group_rule" "all" {
  type              = "egress"
  protocol          = "-1"
  from_port         = 0
  to_port           = 0
  cidr_blocks         = ["0.0.0.0/0"]
  description       = "All egress"
  security_group_id = aws_security_group.lb_enclave.id
}
