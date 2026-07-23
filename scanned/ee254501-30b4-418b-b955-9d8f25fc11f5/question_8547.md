# Q8547: IsSwapTx counter drift under concurrent execution

## Question
Can an unprivileged attacker reach `IsSwapTx` through gasless counter or auction execution update path using signed bid or sponsored payload bytes, counters, domain fields, fee terms, and submission timing and make `IsSwapTx` execute two state changes off the same logical counter value, causing the invariant that counter advancement must be atomic across parallel submissions to fail and leading to Unauthorized transaction?

## Target
- File/function: kaiax/gasless/impl/getter.go:92 (IsSwapTx)
- Entrypoint: gasless counter or auction execution update path
- Attacker controls: signed bid or sponsored payload bytes, counters, domain fields, fee terms, and submission timing
- Exploit idea: make `IsSwapTx` execute two state changes off the same logical counter value
- Invariant to test: counter advancement must be atomic across parallel submissions
- Expected Immunefi impact: Unauthorized transaction
- Fast validation: race parallel submissions against the same counter and assert only one state change can commit
