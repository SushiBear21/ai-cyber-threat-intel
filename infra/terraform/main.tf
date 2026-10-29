terraform {
  required_version = ">= 1.10.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  region              = "us-east-1"
  profile             = "portfolio-sandbox"
  allowed_account_ids = ["359769212511"]

  default_tags {
    tags = {
      Project     = "AICyberThreatIntel"
      Environment = "Sandbox"
      ManagedBy   = "Terraform"
      DataClass   = "PublicAndSynthetic"
    }
  }
}

resource "aws_s3_bucket" "data" {
  bucket_prefix = "ai-cti-359769212511-"
  force_destroy = false
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket = aws_s3_bucket.data.id

  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "data" {
  bucket = aws_s3_bucket.data.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "data" {
  bucket = aws_s3_bucket.data.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.data.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_policy" "data" {
  bucket = aws_s3_bucket.data.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource = [
        aws_s3_bucket.data.arn,
        "${aws_s3_bucket.data.arn}/*"
      ]
      Condition = {
        Bool = {
          "aws:SecureTransport"       = "false"
          "aws:PrincipalIsAWSService" = "false"
        }
      }
    }]
  })

  depends_on = [aws_s3_bucket_public_access_block.data]
}

resource "aws_cloudwatch_log_group" "worker" {
  name              = "/aws/lambda/ai-cti-worker"
  retention_in_days = 14
}

resource "aws_iam_role" "worker" {
  name = "ai-cti-worker"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "worker" {
  name = "ai-cti-worker-permissions"
  role = aws_iam_role.worker.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ReadExplicitInput"
        Effect   = "Allow"
        Action   = "s3:GetObject"
        Resource = "${aws_s3_bucket.data.arn}/inputs/prioritized.json"
      },
      {
        Sid      = "WriteRunArtifacts"
        Effect   = "Allow"
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.data.arn}/runs/*"
      },
      {
        Sid      = "GenerateSummaries"
        Effect   = "Allow"
        Action   = "bedrock:InvokeModel"
        Resource = "arn:aws:bedrock:us-east-1::foundation-model/amazon.nova-lite-v1:0"
      },
      {
        Sid    = "WriteWorkerLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "${aws_cloudwatch_log_group.worker.arn}:*"
      }
    ]
  })
}
resource "aws_lambda_function" "worker" {
  function_name = "ai-cti-worker"
  role          = aws_iam_role.worker.arn
  runtime       = "python3.13"
  handler       = "app.scheduled_worker.lambda_handler"

  filename         = "${path.module}/../../.build/worker.zip"
  source_code_hash = filebase64sha256("${path.module}/../../.build/worker.zip")

  timeout     = 600
  memory_size = 256

  environment {
    variables = {
      DATA_BUCKET = aws_s3_bucket.data.id
      RUN_TABLE   = aws_dynamodb_table.runs.name
    }
  }

  depends_on = [
    aws_iam_role_policy.worker,
    aws_iam_role_policy.worker_automation,
    aws_cloudwatch_log_group.worker
  ]
}

output "data_bucket_name" {
  value = aws_s3_bucket.data.id
}

output "worker_function_name" {
  value = aws_lambda_function.worker.function_name
}
