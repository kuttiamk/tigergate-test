provider "google" {
  project = "tigergate-project"
  region  = "us-central1"
}
resource "google_storage_bucket" "open_bucket" {
  name          = "tigergate-gcp-open-bucket"
  location      = "US"
  force_destroy = true
}
resource "google_storage_bucket_iam_binding" "public_access" {
  bucket = google_storage_bucket.open_bucket.name
  role   = "roles/storage.objectViewer"
  members = [
    "allUsers", # CSPM alert
  ]
}
