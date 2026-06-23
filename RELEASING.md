# Releasing ZMap

This document covers everything needed to cut a ZMap release: the pre-release
commit, mandatory staging verification, tagging, and the one-time GCP
infrastructure setup for whoever inherits this role.

## Prerequisites

- Write access to `zmap/zmap` on GitHub
- Ability to trigger GitHub Actions workflows manually
- For first-time setup only: owner access to the ZMap GCP project

---

## 1. Pre-release commit

Open a PR against `main` with the following three changes. See
[#976](https://github.com/zmap/zmap/pull/976) as an example.

### a. Bump the version in `CMakeLists.txt`

```cmake
# Line 3
set(ZMAP_VERSION v4.5.0)
```

### b. Update `CHANGELOG.md`

Add a new section at the bottom following the existing format:

```
# 4.5.0 2026-MM-DD

## FEATURE
* ...

## ENHANCEMENT
* ...

## BUGFIX
* ...
```

### c. Update the version in `README.md`

```
The latest stable release of ZMap is [4.5.0](https://github.com/zmap/zmap/releases/tag/v4.5.0) ...
```

Merge the PR once reviewed.

---

## 2. Verify staging (required before tagging)

Run the APT publish pipeline against staging and confirm the install works
before pushing a real tag. This takes about 5 minutes.

**Trigger the staging run:**

1. Go to **Actions → Publish APT Package → Run workflow**
2. Leave the `environment` dropdown on **staging** (the default)
3. Click **Run workflow**

**Confirm the packages install correctly:**

```bash
docker run --rm -it ubuntu:24.04 bash -c "
  apt-get update -q && apt-get install -y -q curl gpg &&
  curl -fsSL https://storage.googleapis.com/zmap-apt-repo-staging/gpg.key \
    | gpg --dearmor -o /usr/share/keyrings/zmap-archive-keyring.gpg &&
  echo 'deb [arch=amd64 signed-by=/usr/share/keyrings/zmap-archive-keyring.gpg] \
    https://storage.googleapis.com/zmap-apt-repo-staging stable main' \
    > /etc/apt/sources.list.d/zmap.list &&
  apt-get update && apt-get install -y zmap &&
  zmap --version"
```

Do not proceed to step 3 until this prints the expected version.

---

## 3. Create and push the release tag

```bash
git checkout main && git pull
git tag v4.5.0
git push origin v4.5.0
```

This triggers two workflows automatically:
- **Docker** (`docker-publish.yml`) — pushes `ghcr.io/zmap/zmap:4.5.0`
- **APT Publish** (`apt-publish.yml`) — builds `.deb` packages for `amd64`
  and `arm64` and publishes them to `gs://zmap-apt-repo`

Then create the GitHub Release through the web UI (or `gh release create
v4.5.0 --notes-from-tag`) so users get a release page with the changelog.

---

## 4. Verify production

After the `apt-publish` workflow completes, confirm the packages are live:

```bash
docker run --rm -it ubuntu:24.04 bash -c "
  apt-get update -q && apt-get install -y -q curl gpg &&
  curl -fsSL https://storage.googleapis.com/zmap-apt-repo/gpg.key \
    | gpg --dearmor -o /usr/share/keyrings/zmap-archive-keyring.gpg &&
  echo 'deb [arch=amd64 signed-by=/usr/share/keyrings/zmap-archive-keyring.gpg] \
    https://storage.googleapis.com/zmap-apt-repo stable main' \
    > /etc/apt/sources.list.d/zmap.list &&
  apt-get update && apt-get install -y zmap &&
  zmap --version"
```

---

## One-time GCP infrastructure setup

This only needs to be done once (or when rebuilding the infrastructure from
scratch). The script `scripts/gcp-apt-setup.sh` automates all of it.

### What it creates

| Resource | Purpose |
|---|---|
| GCS bucket `zmap-apt-repo` | Hosts the public APT repository |
| GCS bucket `zmap-apt-repo-staging` | Staging target for pre-release testing |
| Service account `apt-publisher` | Identity used by GitHub Actions to write to GCS |
| Secret Manager secret `zmap-apt-signing-key` | GPG private key used to sign packages |
| Workload Identity Federation pool + provider | Lets GitHub Actions authenticate to GCP without a long-lived key |

### Run the setup script

```bash
gcloud auth login
bash scripts/gcp-apt-setup.sh <gcp-project-id>
```

The script prints the three values you need at the end. Add them as GitHub
Actions secrets on the `zmap/zmap` repo (`Settings → Secrets → Actions`):

| Secret name | Value |
|---|---|
| `GCP_PROJECT_ID` | Your GCP project ID |
| `GCP_WORKLOAD_IDENTITY_PROVIDER` | Printed by the setup script |
| `GCP_SERVICE_ACCOUNT` | `apt-publisher@<project-id>.iam.gserviceaccount.com` |

### GPG key rotation

The signing key is an Ed25519 key with no expiry. Rotation is only needed if
the key is compromised. The `rotate-apt-key` workflow handles it: it generates
a new key, stores it as a new Secret Manager version, re-signs the repository
index, and uploads the updated public key to `storage.googleapis.com/zmap-apt-repo/gpg.key`.

To rotate:

1. Go to **Actions → Rotate APT Signing Key → Run workflow**
2. Click **Run workflow**
3. Notify end users to re-fetch the public key:
   ```bash
   curl -fsSL https://storage.googleapis.com/zmap-apt-repo/gpg.key | sudo gpg --dearmor -o /usr/share/keyrings/zmap-archive-keyring.gpg
   ```
