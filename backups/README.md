# Local database backups

The Compose maintenance profile writes compressed PostgreSQL dumps here. Backup files are
ignored by Git. Production operators must copy encrypted backups to a separate machine and
regularly test restoration.
