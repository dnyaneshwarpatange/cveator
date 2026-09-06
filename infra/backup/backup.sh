#!/bin/sh
set -eu
set -o pipefail

: "${PGHOST:?PGHOST must be set}"
: "${PGDATABASE:?PGDATABASE must be set}"
: "${PGUSER:?PGUSER must be set}"
: "${PGPASSWORD:?PGPASSWORD must be set}"

backup_directory=/backups
retention_days="${BACKUP_RETENTION_DAYS:-14}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
temporary_path="${backup_directory}/.${PGDATABASE}-${timestamp}.sql.gz.tmp"
final_path="${backup_directory}/${PGDATABASE}-${timestamp}.sql.gz"

mkdir -p "${backup_directory}"
pg_dump --format=plain --no-owner --no-privileges | gzip -9 > "${temporary_path}"
gzip -t "${temporary_path}"
mv "${temporary_path}" "${final_path}"
find "${backup_directory}" -type f -name "${PGDATABASE}-*.sql.gz" -mtime "+${retention_days}" -delete
echo "Database backup written to ${final_path}"
