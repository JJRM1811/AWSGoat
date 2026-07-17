resource "aws_ecr_repository" "aws_goat_m2_fixed" {
  name                 = "aws-goat-m2-fixed"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = {
    Project     = "AWSGoat"
    Module      = "module-2"
    Environment = "remediacion"
  }
}

output "ecr_repository_url" {
  value       = aws_ecr_repository.aws_goat_m2_fixed.repository_url
  description = "URI del repositorio ECR para la imagen remediada del Modulo 2"
}
