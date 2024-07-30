resource "aws_dynamodb_table" "glove" {
  name           = "glove"
  billing_mode   = "PROVISIONED"
  read_capacity  = 20
  write_capacity = 20
  hash_key       = "partitionKey"
  range_key      = "sortKey"
  attribute {
    name = "partitionKey"
    type = "S"
  }
  attribute {
    name = "sortKey"
    type = "S"
  }
  tags = {
    Environment = "test"
    Name        = "Glove"
  }
}
