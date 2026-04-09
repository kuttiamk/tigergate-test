resource "aws_iam_policy" "admin_policy" {
  name        = "super-admin-policy"
  description = "Excessive permissions"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action   = "*" # CIEM alert
        Effect   = "Allow"
        Resource = "*" # CIEM alert
      },
    ]
  })
}
