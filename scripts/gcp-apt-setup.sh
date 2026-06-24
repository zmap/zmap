#!/usr/bin/env bash
# One-time setup for the ZMap APT repository on GCP.
# Run this once from a machine authenticated as a GCP project owner.
#
# Prerequisites:
#   gcloud CLI installed and authenticated (gcloud auth login)
#   gpg installed
#
# After running this script, add three GitHub Actions secrets to the zmap/zmap repo:
#   GCP_PROJECT_ID               — your GCP project ID
#   GCP_WORKLOAD_IDENTITY_PROVIDER — printed at the end of this script
#   GCP_SERVICE_ACCOUNT          — printed at the end of this script
set -euo pipefail

PROJECT_ID="${1:?Usage: $0 <gcp-project-id>}"
REPO="zmap/zmap"
BUCKET="zmap-apt-repo"
SA_NAME="apt-publisher"
SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"
POOL_ID="github-actions"
PROVIDER_ID="github"

echo "==> Enabling required GCP APIs"
gcloud services enable \
  storage.googleapis.com \
  secretmanager.googleapis.com \
  iamcredentials.googleapis.com \
  sts.googleapis.com \
  --project="$PROJECT_ID"

echo "==> Creating GCS bucket: gs://$BUCKET"
gcloud storage buckets create "gs://$BUCKET" \
  --project="$PROJECT_ID" \
  --location=US \
  --uniform-bucket-level-access

echo "==> Making bucket publicly readable"
gcloud storage buckets add-iam-policy-binding "gs://$BUCKET" \
  --member="allUsers" \
  --role="roles/storage.objectViewer"

echo "==> Creating staging bucket: gs://zmap-apt-repo-staging"
gcloud storage buckets create "gs://zmap-apt-repo-staging" \
  --project="$PROJECT_ID" \
  --location=US \
  --uniform-bucket-level-access
gcloud storage buckets add-iam-policy-binding "gs://zmap-apt-repo-staging" \
  --member="allUsers" \
  --role="roles/storage.objectViewer"

echo "==> Creating service account: $SA_EMAIL"
gcloud iam service-accounts create "$SA_NAME" \
  --project="$PROJECT_ID" \
  --display-name="APT Repository Publisher"

echo "==> Granting service account write access to buckets"
gcloud storage buckets add-iam-policy-binding "gs://$BUCKET" \
  --member="serviceAccount:$SA_EMAIL" \
  --role="roles/storage.objectAdmin"
gcloud storage buckets add-iam-policy-binding "gs://zmap-apt-repo-staging" \
  --member="serviceAccount:$SA_EMAIL" \
  --role="roles/storage.objectAdmin"

echo "==> Granting service account access to Secret Manager"
gcloud projects add-iam-policy-binding "$PROJECT_ID" \
  --member="serviceAccount:$SA_EMAIL" \
  --role="roles/secretmanager.secretAccessor"
# secretVersionAdder is required for automated key rotation
gcloud projects add-iam-policy-binding "$PROJECT_ID" \
  --member="serviceAccount:$SA_EMAIL" \
  --role="roles/secretmanager.secretVersionAdder"

echo "==> Creating Workload Identity Pool"
gcloud iam workload-identity-pools create "$POOL_ID" \
  --project="$PROJECT_ID" \
  --location="global" \
  --display-name="GitHub Actions"

POOL_NAME=$(gcloud iam workload-identity-pools describe "$POOL_ID" \
  --project="$PROJECT_ID" \
  --location="global" \
  --format="value(name)")

echo "==> Creating OIDC provider for GitHub"
gcloud iam workload-identity-pools providers create-oidc "$PROVIDER_ID" \
  --project="$PROJECT_ID" \
  --location="global" \
  --workload-identity-pool="$POOL_ID" \
  --display-name="GitHub" \
  --issuer-uri="https://token.actions.githubusercontent.com" \
  --attribute-mapping="google.subject=assertion.sub,attribute.repository=assertion.repository,attribute.actor=assertion.actor,attribute.ref=assertion.ref" \
  --attribute-condition="assertion.repository=='${REPO}'"

echo "==> Binding GitHub repo to service account"
gcloud iam service-accounts add-iam-policy-binding "$SA_EMAIL" \
  --project="$PROJECT_ID" \
  --role="roles/iam.workloadIdentityUser" \
  --member="principalSet://iam.googleapis.com/${POOL_NAME}/attribute.repository/${REPO}"

echo "==> Generating GPG signing key (no passphrase — stored in Secret Manager)"
GPG_KEY_EMAIL="zmap-apt@zmap.io"
gpg --batch --gen-key <<EOF
%no-protection
Key-Type: EdDSA
Key-Curve: ed25519
Subkey-Type: ECDH
Subkey-Curve: cv25519
Name-Real: ZMap Project
Name-Email: ${GPG_KEY_EMAIL}
Expire-Date: 0
%commit
EOF

echo "==> Storing private key in Secret Manager"
gpg --armor --export-secret-keys "$GPG_KEY_EMAIL" | \
  gcloud secrets create "zmap-apt-signing-key" \
    --project="$PROJECT_ID" \
    --data-file=-

echo "==> Uploading public key to GCS bucket"
gpg --armor --export "$GPG_KEY_EMAIL" > /tmp/zmap-apt-gpg.key
gcloud storage cp /tmp/zmap-apt-gpg.key "gs://${BUCKET}/gpg.key"
rm -f /tmp/zmap-apt-gpg.key

PROVIDER_RESOURCE=$(gcloud iam workload-identity-pools providers describe "$PROVIDER_ID" \
  --project="$PROJECT_ID" \
  --location="global" \
  --workload-identity-pool="$POOL_ID" \
  --format="value(name)")

echo ""
echo "============================================================"
echo "Setup complete. Add these secrets to the GitHub repo:"
echo ""
echo "  GCP_PROJECT_ID:                  $PROJECT_ID"
echo "  GCP_WORKLOAD_IDENTITY_PROVIDER:  $PROVIDER_RESOURCE"
echo "  GCP_SERVICE_ACCOUNT:             $SA_EMAIL"
echo "============================================================"
echo ""
echo "User install snippet for README:"
echo "  curl -fsSL https://storage.googleapis.com/zmap-apt-repo/gpg.key | sudo gpg --dearmor -o /usr/share/keyrings/zmap-archive-keyring.gpg"
echo "  echo \"deb [arch=\$(dpkg --print-architecture) signed-by=/usr/share/keyrings/zmap-archive-keyring.gpg] https://storage.googleapis.com/zmap-apt-repo stable main\" | sudo tee /etc/apt/sources.list.d/zmap.list"
echo "  sudo apt update && sudo apt install zmap"
