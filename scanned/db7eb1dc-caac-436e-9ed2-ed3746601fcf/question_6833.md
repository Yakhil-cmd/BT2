# Q6833: Lock counterpart authorization gap

## Question
Can an unprivileged attacker reach `Lock` through mainbridge or subbridge message execution or counterpart bridge callback using asset address, amount, recipient, fee fields, extraData, counterpart message fields, and replay timing and make `Lock` execute a message from a non-canonical counterpart bridge, causing the invariant that only the configured counterpart bridge may authorize outbound asset release to fail and leading to Unauthorized transaction?

## Target
- File/function: node/sc/bridge_accounts.go:305 (Lock)
- Entrypoint: mainbridge or subbridge message execution or counterpart bridge callback
- Attacker controls: asset address, amount, recipient, fee fields, extraData, counterpart message fields, and replay timing
- Exploit idea: make `Lock` execute a message from a non-canonical counterpart bridge
- Invariant to test: only the configured counterpart bridge may authorize outbound asset release
- Expected Immunefi impact: Unauthorized transaction
- Fast validation: forge counterpart messages from a non-authorized sender on a local setup and assert release paths always reject them
