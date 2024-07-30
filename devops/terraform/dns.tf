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

resource "aws_route53_record" "validation_test" {
  for_each = {
    for dvo in aws_acm_certificate.test.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  }
  allow_overwrite = true
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 60
  type            = each.value.type
  zone_id         = aws_route53_zone.test.zone_id
}

resource "aws_acm_certificate_validation" "test" {
  certificate_arn         = aws_acm_certificate.test.arn
  validation_record_fqdns = [for record in aws_route53_record.validation_test : record.fqdn]
}

resource "aws_acm_certificate" "test" {
  domain_name       = "*.test.projectglove.io"
  validation_method = "DNS"
  tags = {
    Environment = "test"
    Name        = "Glove"
  }
  lifecycle {
    create_before_destroy = true
  }
}
