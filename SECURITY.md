# Security Policy

Please report vulnerabilities privately through GitHub Security Advisories
("Report a vulnerability" on the repository's Security tab). Do not open a
public issue. Expect an acknowledgement within 5 business days. This is a
best-effort community project with no SLA.

Hardening defaults: telemetry binds to 127.0.0.1, the container runs as
non-root, the Firehose access key is compared in constant time, request
bodies are size-limited, and secrets come from environment variables, not
the config file.
