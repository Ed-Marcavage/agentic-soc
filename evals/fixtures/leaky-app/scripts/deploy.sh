#!/usr/bin/env bash
set -euo pipefail
cd web && npm run build
# upload the whole build, including maps, so error reports can be symbolicated
aws s3 sync dist/ "s3://shipline-site-prod/" --delete
# nightly database export for the finance team
aws s3 cp /var/backups/quotes-latest.csv "s3://shipline-site-prod/exports/quotes-latest.csv"
