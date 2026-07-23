# Q5441: LockParentOperator fee-limit bypass

## Question
Can an unprivileged attacker reach `LockParentOperator` through bridge transfer path that charges relay or settlement fees using asset address, amount, recipient, fee fields, extraData, counterpart message fields, and replay timing and make `LockParentOperator` settle a transfer while undercharging or bypassing the configured bridge fee, causing the invariant that every settled bridge transfer must satisfy the configured fee policy before release to fail and leading to Fee payment bypass?

## Target
- File/function: node/sc/sub_bridge_handler.go:101 (LockParentOperator)
- Entrypoint: bridge transfer path that charges relay or settlement fees
- Attacker controls: asset address, amount, recipient, fee fields, extraData, counterpart message fields, and replay timing
- Exploit idea: make `LockParentOperator` settle a transfer while undercharging or bypassing the configured bridge fee
- Invariant to test: every settled bridge transfer must satisfy the configured fee policy before release
- Expected Immunefi impact: Fee payment bypass
- Fast validation: send transfers at rounding and limit boundaries and compare charged fees against configured bridge policy
