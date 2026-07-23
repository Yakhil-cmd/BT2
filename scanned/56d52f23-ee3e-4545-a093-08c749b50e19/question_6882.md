# Q6882: handle fee-limit bypass

## Question
Can an unprivileged attacker reach `handle` through bridge transfer path that charges relay or settlement fees using asset address, amount, recipient, fee fields, extraData, counterpart message fields, and replay timing and make `handle` settle a transfer while undercharging or bypassing the configured bridge fee, causing the invariant that every settled bridge transfer must satisfy the configured fee policy before release to fail and leading to Fee payment bypass?

## Target
- File/function: node/sc/mainbridge.go:361 (handle)
- Entrypoint: bridge transfer path that charges relay or settlement fees
- Attacker controls: asset address, amount, recipient, fee fields, extraData, counterpart message fields, and replay timing
- Exploit idea: make `handle` settle a transfer while undercharging or bypassing the configured bridge fee
- Invariant to test: every settled bridge transfer must satisfy the configured fee policy before release
- Expected Immunefi impact: Fee payment bypass
- Fast validation: send transfers at rounding and limit boundaries and compare charged fees against configured bridge policy
