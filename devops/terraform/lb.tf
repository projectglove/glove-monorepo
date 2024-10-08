resource "aws_lb" "enclave" {
  name                       = "enclave"
  internal                   = false
  load_balancer_type         = "application"
  security_groups            = [aws_security_group.lb_enclave.id]
  subnets                    = [for s in data.aws_subnets.default.ids : s]
  enable_deletion_protection = true
}

resource "aws_lb_listener" "enclave-http" {
  load_balancer_arn = aws_lb.enclave.arn
  port              = "80"
  protocol          = "HTTP"
  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

resource "aws_lb_listener" "enclave-https" {
  load_balancer_arn = aws_lb.enclave.arn
  port              = "443"
  protocol          = "HTTPS"
  certificate_arn   = aws_acm_certificate_validation.test.certificate_arn
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.enclave.arn
  }
}

resource "aws_lb_target_group" "enclave" {
  name     = "enclave"
  port     = 80
  protocol = "HTTP"
  vpc_id   = data.aws_vpc.default.id
  health_check {
    path = "/info"
  }
}

resource "aws_lb_target_group_attachment" "enclave" {
  target_group_arn = aws_lb_target_group.enclave.arn
  target_id        = aws_instance.enclave.id
  port             = 8080
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
  cidr_blocks       = ["0.0.0.0/0"]
  description       = "HTTP web traffic"
  security_group_id = aws_security_group.lb_enclave.id
}

resource "aws_security_group_rule" "https" {
  type              = "ingress"
  protocol          = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_blocks       = ["0.0.0.0/0"]
  description       = "HTTPS web traffic"
  security_group_id = aws_security_group.lb_enclave.id
}

resource "aws_security_group_rule" "all" {
  type              = "egress"
  protocol          = "-1"
  from_port         = 0
  to_port           = 0
  cidr_blocks       = ["0.0.0.0/0"]
  description       = "All egress"
  security_group_id = aws_security_group.lb_enclave.id
}
