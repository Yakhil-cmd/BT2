# Q6904: ConvertChildChainBlockHashToParentChainTxHash counterpart authorization gap

## Question
Can an unprivileged attacker reach `ConvertChildChainBlockHashToParentChainTxHash` through mainbridge or subbridge message execution or counterpart bridge callback using asset address, amount, recipient, fee fields, extraData, counterpart message fields, and replay timing and make `ConvertChildChainBlockHashToParentChainTxHash` execute a message from a non-canonical counterpart bridge, causing the invariant that only the configured counterpart bridge may authorize outbound asset release to fail and leading to Unauthorized transaction?

## Target
- File/function: node/sc/sub_event_handler.go:111 (ConvertChildChainBlockHashToParentChainTxHash)
- Entrypoint: mainbridge or subbridge message execution or counterpart bridge callback
- Attacker controls: asset address, amount, recipient, fee fields, extraData, counterpart message fields, and replay timing
- Exploit idea: make `ConvertChildChainBlockHashToParentChainTxHash` execute a message from a non-canonical counterpart bridge
- Invariant to test: only the configured counterpart bridge may authorize outbound asset release
- Expected Immunefi impact: Unauthorized transaction
- Fast validation: forge counterpart messages from a non-authorized sender on a local setup and assert release paths always reject them
