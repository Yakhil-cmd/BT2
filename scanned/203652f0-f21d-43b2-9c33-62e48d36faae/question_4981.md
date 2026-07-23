# Q4981: addVerifiedMessage fork-choice desync

## Question
Can an unprivileged attacker reach `addVerifiedMessage` through peer announcements, block import, and canonical-head selection using header and body fields, ancestry claims, seal bytes, validator ordering, and packet timing and make `addVerifiedMessage` prefer an invalid or stale branch long enough to execute stateful side effects, causing the invariant that fork choice must not expose transient invalid state as canonical to fail and leading to Balance manipulation?

## Target
- File/function: consensus/istanbul/core/message_set.go:121 (addVerifiedMessage)
- Entrypoint: peer announcements, block import, and canonical-head selection
- Attacker controls: header and body fields, ancestry claims, seal bytes, validator ordering, and packet timing
- Exploit idea: make `addVerifiedMessage` prefer an invalid or stale branch long enough to execute stateful side effects
- Invariant to test: fork choice must not expose transient invalid state as canonical
- Expected Immunefi impact: Balance manipulation
- Fast validation: reorder competing branch announcements and verify stateful consumers never observe an invalid canonical branch
