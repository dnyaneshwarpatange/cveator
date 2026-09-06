# Self-hosted S3 storage decision

Application code uses the `StorageProvider` port and an isolated S3-protocol adapter. It can
connect to MinIO, Garage, Ceph RGW, or another S3-compatible endpoint without changing core
logic.

The original build specification selected MinIO. As of April 2026, the upstream community
repository is archived and its maintainers describe the community edition as source-only;
historical container binaries are not maintained. This repository therefore does not pin an
obsolete MinIO container and present it as production-ready.

For production, operate a maintained S3-compatible cluster on infrastructure you control,
create a private bucket and restricted application key, then populate the generic
`STORAGE_*` settings. A single object-storage process on the same VPS is not a backup or a
high-availability deployment.
