# Differences between v6 GCF Format and Current Generator

All discrepancies identified from the v6 specification have been resolved. The generator now
matches the documented layout:

- Block allocation entries use 16‑bit flag and dummy fields.
- A block‑entry map is emitted for every archive.
- Manifest headers receive a randomized fingerprint on each build.
- Checksum maps carry an RSA signature and only store the latest application version in the footer.
- Block entry flags are configurable per file instead of hard‑coded.
