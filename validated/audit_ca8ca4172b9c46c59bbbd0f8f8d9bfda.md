Looking at the external report's vulnerability class — **state not reset/invalidated after use, enabling double-claim** — I need to find an analog where cryptographic state (nonces, presignatures) is not properly invalidated after consumption, allowing reuse.

Let me examine the FROST presign/sign flow in detail.