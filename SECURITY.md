# Security policy

## Reporting a vulnerability

Please do **not** open a public issue for security problems. Use GitHub's
[private vulnerability reporting](https://github.com/HuntsmanSec/stark/security/advisories/new).
We aim to acknowledge reports within 5 working days.

## Handling of secrets

- API keys are read from environment variables or the local config file (`0600` on POSIX).
- Keys are masked in `stark config show` and are never written to output, logs or the cache.
- The result cache (`stark cache path`) stores lookup results only. Clear it with `stark cache clear`.
