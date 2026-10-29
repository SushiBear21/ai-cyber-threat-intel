variable "schedule_enabled" {
  type    = bool
  default = false
}

variable "schedule_expression" {
  type    = string
  default = "cron(0 9 * * ? *)"
}

resource "aws_dynamodb_table" "runs" {
  name         = "ai-cti-runs"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "run_id"

  attribute {
    name = "run_id"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }
}

resource "aws_sqs_queue" "failures" {
  name                      = "ai-cti-failures"
  message_retention_seconds = 1209600
  sqs_managed_sse_enabled   = true
}

resource "aws_iam_role_policy" "worker_automation" {
  name = "ai-cti-worker-automation"
  role = aws_iam_role.worker.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReadSyntheticConfiguration"
        Effect = "Allow"
        Action = "s3:GetObject"
        Resource = [
          "${aws_s3_bucket.data.arn}/inputs/assets.json",
          "${aws_s3_bucket.data.arn}/inputs/review-rules.json"
        ]
      },
      {
        Sid    = "TrackRuns"
        Effect = "Allow"
        Action = [
          "dynamodb:PutItem",
          "dynamodb:GetItem",
          "dynamodb:UpdateItem"
        ]
        Resource = aws_dynamodb_table.runs.arn
      },
      {
        Sid      = "RetainFailedAsyncInvocations"
        Effect   = "Allow"
        Action   = "sqs:SendMessage"
        Resource = aws_sqs_queue.failures.arn
      }
    ]
  })
}

resource "aws_lambda_function_event_invoke_config" "worker" {
  function_name                = aws_lambda_function.worker.function_name
  maximum_event_age_in_seconds = 3600
  maximum_retry_attempts       = 0

  destination_config {
    on_failure {
      destination = aws_sqs_queue.failures.arn
    }
  }

  depends_on = [aws_iam_role_policy.worker_automation]
}

resource "aws_scheduler_schedule_group" "cti" {
  name = "ai-cti"
}

resource "aws_iam_role" "scheduler" {
  name = "ai-cti-scheduler"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "scheduler.amazonaws.com"
      }
      Action = "sts:AssumeRole"
      Condition = {
        StringEquals = {
          "aws:SourceAccount" = "359769212511"
        }
        ArnEquals = {
          "aws:SourceArn" = aws_scheduler_schedule_group.cti.arn
        }
      }
    }]
  })
}

resource "aws_iam_role_policy" "scheduler" {
  name = "invoke-ai-cti-worker"
  role = aws_iam_role.scheduler.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "lambda:InvokeFunction"
        Resource = aws_lambda_function.worker.arn
      },
      {
        Effect   = "Allow"
        Action   = "sqs:SendMessage"
        Resource = aws_sqs_queue.failures.arn
      }
    ]
  })
}

resource "aws_scheduler_schedule" "worker" {
  name                         = "ai-cti-daily"
  group_name                   = aws_scheduler_schedule_group.cti.name
  schedule_expression          = var.schedule_expression
  schedule_expression_timezone = "UTC"
  state                        = var.schedule_enabled ? "ENABLED" : "DISABLED"

  flexible_time_window {
    mode = "OFF"
  }

  target {
    arn      = aws_lambda_function.worker.arn
    role_arn = aws_iam_role.scheduler.arn
    input    = jsonencode({ trigger = "scheduler" })

    retry_policy {
      maximum_event_age_in_seconds = 3600
      maximum_retry_attempts       = 1
    }

    dead_letter_config {
      arn = aws_sqs_queue.failures.arn
    }
  }

  depends_on = [
    aws_iam_role_policy.scheduler,
    aws_lambda_function_event_invoke_config.worker
  ]
}

resource "aws_sns_topic" "operations" {
  name = "ai-cti-operations"
}

resource "aws_cloudwatch_metric_alarm" "worker_errors" {
  alarm_name          = "ai-cti-worker-errors"
  namespace           = "AWS/Lambda"
  metric_name         = "Errors"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"

  dimensions = {
    FunctionName = aws_lambda_function.worker.function_name
  }

  alarm_actions = [aws_sns_topic.operations.arn]
  ok_actions    = [aws_sns_topic.operations.arn]
}

resource "aws_cloudwatch_metric_alarm" "worker_duration" {
  alarm_name          = "ai-cti-worker-long-duration"
  namespace           = "AWS/Lambda"
  metric_name         = "Duration"
  statistic           = "Maximum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 480000
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"

  dimensions = {
    FunctionName = aws_lambda_function.worker.function_name
  }

  alarm_actions = [aws_sns_topic.operations.arn]
}

resource "aws_cloudwatch_metric_alarm" "failure_queue" {
  alarm_name          = "ai-cti-failure-queue-not-empty"
  namespace           = "AWS/SQS"
  metric_name         = "ApproximateNumberOfMessagesVisible"
  statistic           = "Maximum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"

  dimensions = {
    QueueName = aws_sqs_queue.failures.name
  }

  alarm_actions = [aws_sns_topic.operations.arn]
}

output "operations_topic_arn" {
  value = aws_sns_topic.operations.arn
}

output "failure_queue_url" {
  value = aws_sqs_queue.failures.url
}