# gpg-service
FastAPI-based proof-of-concept for a remote GPG-agent REST service that:  🔐 Stores each user’s private key encrypted at rest (using a password-derived key).  ⚙️ Unlocks and uses the private key in-memory for signing/verifying.  🚀 Supports secure API key authentication for each user.
