# Q8541: IsBundleTx counter drift under concurrent execution

## Question
Can an unprivileged attacker reach `IsBundleTx` through gasless counter or auction execution update path using signed bid or sponsored payload bytes, counters, domain fields, fee terms, and submission timing and make `IsBundleTx` execute two state changes off the same logical counter value, causing the invariant that counter advancement must be atomic across parallel submissions to fail and leading to Unauthorized transaction?

## Target
- File/function: kaiax/gasless/impl/builder.go:74 (IsBundleTx)
- Entrypoint: gasless counter or auction execution update path
- Attacker controls: signed bid or sponsored payload bytes, counters, domain fields, fee terms, and submission timing
- Exploit idea: make `IsBundleTx` execute two state changes off the same logical counter value
- Invariant to test: counter advancement must be atomic across parallel submissions
- Expected Immunefi impact: Unauthorized transaction
- Fast validation: race parallel submissions against the same counter and assert only one state change can commit
