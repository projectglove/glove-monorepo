resource "aws_route53_zone" "test" {
  name = "test.projectglove.io"
}

resource "aws_route53_record" "enclave" {
  zone_id = aws_route53_zone.test.zone_id
  name    = "enclave.test.projectglove.io"
  type    = "A"
  alias {
    name                   = aws_lb.enclave.dns_name
    zone_id                = aws_lb.enclave.zone_id
    evaluate_target_health = true
  }
}
