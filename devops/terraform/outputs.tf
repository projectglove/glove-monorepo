output "ip" {
  value = aws_instance.enclave.public_ip
}

output "name_servers" {
  value = aws_route53_zone.test.name_servers
}
