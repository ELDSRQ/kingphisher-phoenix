# Privacy export authorization boundary

The operator application enforces HANDLE_PRIVACY, verifies the request state,
decrypts the requested mailbox, matches its salted lookup to the subject rows,
and computes each subject's governed HMAC pseudonym. It returns minimized
receipt fields and bounded current-key-version ledger history with explicit
unavailable/truncated status.

The managed database function authenticates the actual operator login, checks
that the supplied request is verified and the subject exists, validates selector
shape/scope/version/bounds, and projects only the minimized ledger columns.
PostgreSQL has neither the application's mailbox-decryption key nor its HMAC
key. It cannot independently prove the supplied request, subject and pseudonym
belong together. That identity binding is an application authorization boundary.

This is bounded service-role access, not per-subject database row security.
The operator database role already manages recipient and privacy-request records.
A compromised operator SQL login can enumerate ledger selectors and invoke the
projection for them; a verified request is not a cryptographic access token.
Denied direct outcome-table reads and private receipt identifiers must not be
represented as isolation against that service-role compromise. A separate
privacy service or independently signed subject capability would be a different
architecture requiring its own keys and operational policy.

Actual-role tests establish that the approved API path works with the minimal
grants, returns the exact requested subject and omits raw selectors/provider
identifiers. They separately establish login restrictions, bounded projection,
invalid-request refusal and direct-column denial. They do not establish
independent database verification of encrypted subject identity.
