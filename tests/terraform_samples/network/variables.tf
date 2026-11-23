# The prefix of every resource name
variable "prefix" {
  type        = string
  default     = "shop"
  description = "Name prefix"
}

variable "db_password" {
  type    = string
  default = "changeme"
}

variable "admin_login" {
  type      = string
  default   = "admin-login-value"
  sensitive = true
}

variable "ingress_ports" {
  type    = list(number)
  default = [80, 443]
}

output "db_endpoint" {
  value       = aws_db_instance.orders.endpoint
  description = "Endpoint of the orders database"
  sensitive   = true
}
