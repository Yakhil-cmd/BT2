# Q3982: handleServiceChainParentChainInfoRequestMsg counterpart authorization gap

## Question
Can an unprivileged attacker reach `handleServiceChainParentChainInfoRequestMsg` through mainbridge or subbridge message execution or counterpart bridge callback using asset address, amount, recipient, fee fields, extraData, counterpart message fields, and replay timing and make `handleServiceChainParentChainInfoRequestMsg` execute a message from a non-canonical counterpart bridge, causing the invariant that only the configured counterpart bridge may authorize outbound asset release to fail and leading to Unauthorized transaction?

## Target
- File/function: node/sc/main_bridge_handler.go:137 (handleServiceChainParentChainInfoRequestMsg)
- Entrypoint: mainbridge or subbridge message execution or counterpart bridge callback
- Attacker controls: asset address, amount, recipient, fee fields, extraData, counterpart message fields, and replay timing
- Exploit idea: make `handleServiceChainParentChainInfoRequestMsg` execute a message from a non-canonical counterpart bridge
- Invariant to test: only the configured counterpart bridge may authorize outbound asset release
- Expected Immunefi impact: Unauthorized transaction
- Fast validation: forge counterpart messages from a non-authorized sender on a local setup and assert release paths always reject them
