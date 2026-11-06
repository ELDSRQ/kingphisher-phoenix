# Historical tombstone cleanup

Erasure now revisits an existing recipient tombstone by its preserved UUID.
It removes directly linked stores and the exact keyed ledger selector, while
preserving the tombstone marker and original deletion time. It waits for any
in-flight assignment projection before purging ledger rows. Tenant retention
holds block this cleanup under the same policy as a first erasure.

The erasure result and audit identify the number of ledger rows removed, the
key version and the active-version selector scope. `no_matching_rows` means
only that this selector matched no rows. It does not establish that every
historical key version has been cleared.

For a reviewed historical repair, use the preserved subject UUID and the
governed retained pseudonym key/version that originally projected its rows.
Resolve and validate that configuration before beginning the transaction.
Call `erase_recipient_data_with_result` through the authorized privacy service
and record its result through the normal audit transaction. Repeat only for
known retained versions; the key bytes must match the declared version. The
helper never guesses identity from a tombstone mailbox, scans arbitrary
subjects, searches receipt identifiers or chooses a key automatically.

Missing, malformed or mismatched keys are not evidence of successful cleanup.
The API rejects invalid managed erasure configuration before moving a verified
request to in-progress. A correct but different version can return zero; retain
that result as scoped evidence and reconcile the governed key inventory.
Unlinked historical receipts cannot be attributed by this helper and require
their existing governed retention process rather than speculative deletion.

Qualification uses new preserved synthetic databases with actual operator
privileges, multiple ledger rows/versions, unrelated subjects, both receipt
stores, pending directory previews, active holds and concurrent projection.
No production subject was erased as part of this code qualification.
