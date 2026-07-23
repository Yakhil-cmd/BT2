# Q6806: requestERC20Transfer fee-limit bypass

## Question
Can an unprivileged attacker reach `requestERC20Transfer` through bridge transfer path that charges relay or settlement fees via an on-chain bridge contract call using asset address, amount, recipient, fee fields, extraData, counterpart message fields, and replay timing and make `requestERC20Transfer` settle a transfer while undercharging or bypassing the configured bridge fee, causing the invariant that every settled bridge transfer must satisfy the configured fee policy before release to fail and leading to Fee payment bypass?

## Target
- File/function: contracts/service_chain/bridge/BridgeTransferERC20.sol:requestERC20Transfer
- Entrypoint: bridge transfer path that charges relay or settlement fees via an on-chain bridge contract call
- Attacker controls: asset address, amount, recipient, fee fields, extraData, counterpart message fields, and replay timing
- Exploit idea: make `requestERC20Transfer` settle a transfer while undercharging or bypassing the configured bridge fee
- Invariant to test: every settled bridge transfer must satisfy the configured fee policy before release
- Expected Immunefi impact: Fee payment bypass
- Fast validation: send transfers at rounding and limit boundaries and compare charged fees against configured bridge policy
