resource "aws_iam_user" "deploy" {
  name = "deploy"
  path = "/system/
}

resource "aws_iam_group" "ops" {
  name = "ops"
