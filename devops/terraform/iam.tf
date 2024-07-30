resource "aws_iam_role" "enclave" {
  name = "enclave"
  assume_role_policy = jsonencode({
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
  managed_policy_arns   = [data.aws_iam_policy.dynamodb_full.arn]
  description           = "Give EC2 instances access to DynamoDB"
  force_detach_policies = true
}

resource "aws_iam_instance_profile" "enclave" {
  name = "enclave"
  role = aws_iam_role.enclave.name
}
