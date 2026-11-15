provider "aws" {
  region = "us-east-1"
}

# ---- site bucket ----
resource "aws_s3_bucket" "site" {
  bucket = "shipline-site-prod"
}

resource "aws_s3_bucket_policy" "site" {
  bucket = aws_s3_bucket.site.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = "*"
      Action    = ["s3:GetObject", "s3:ListBucket"]
      Resource  = [aws_s3_bucket.site.arn, "${aws_s3_bucket.site.arn}/*"]
    }]
  })
}

# ---- sign-in ----
resource "aws_cognito_user_pool" "main" {
  name = "shipline-users"

  admin_create_user_config {
    allow_admin_create_user_only = false
  }

  schema {
    name                = "tenantId"
    attribute_data_type = "String"
    mutable             = true
  }

  schema {
    name                = "isAdmin"
    attribute_data_type = "String"
    mutable             = true
  }

  lambda_config {
    pre_sign_up = aws_lambda_function.presignup.arn
  }
}

resource "aws_cognito_user_pool_client" "web" {
  name             = "web"
  user_pool_id     = aws_cognito_user_pool.main.id
  generate_secret  = false
  write_attributes = ["email", "custom:tenantId", "custom:isAdmin"]
}

resource "aws_cognito_identity_pool" "main" {
  identity_pool_name               = "shipline"
  allow_unauthenticated_identities = false

  cognito_identity_providers {
    client_id     = aws_cognito_user_pool_client.web.id
    provider_name = aws_cognito_user_pool.main.endpoint
  }
}

resource "aws_iam_role_policy" "authenticated" {
  name = "shipline-authenticated"
  role = aws_iam_role.authenticated.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "s3:*",
        "secretsmanager:ListSecrets",
        "secretsmanager:GetSecretValue",
        "ssm:DescribeParameters",
        "logs:DescribeLogGroups",
        "logs:FilterLogEvents"
      ]
      Resource = "*"
    }]
  })
}

# ---- CI deploy user ----
resource "aws_iam_user" "ci" {
  name = "ci-deploy"
}

resource "aws_iam_user_policy_attachment" "ci_admin" {
  user       = aws_iam_user.ci.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_access_key" "ci" {
  user = aws_iam_user.ci.name
}

# ---- API hosts ----
resource "aws_launch_template" "api" {
  name_prefix   = "shipline-api-"
  image_id      = "ami-0example0000000000"
  instance_type = "t3.small"

  iam_instance_profile {
    name = aws_iam_instance_profile.api.name
  }

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "optional"
  }
}

resource "aws_lambda_function" "presignup" {
  function_name = "shipline-presignup"
  handler       = "presignup.handler"
  runtime       = "nodejs20.x"
  role          = aws_iam_role.lambda.arn
  filename      = "presignup.zip"

  environment {
    variables = {
      TENANT_DB_URL = "postgres://shipline:EXAMPLE-db-password@db.internal.shipline.example:5432/tenants"
    }
  }
}
