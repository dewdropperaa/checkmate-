terraform {
  required_version = ">= 1.5.0"

  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 5.0"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }

  # Optional: uncomment and configure a remote backend before team use.
  # backend "s3" { ... }
}

provider "cloudflare" {
  # Authenticate with CLOUDFLARE_API_TOKEN (env var). Do not hardcode tokens.
  # See README.md for the minimum scoped permissions.
}
