# Q2036: Round consensus message replay

## Question
Can an unprivileged attacker reach `Round` through prepare, preprepare, commit, or round-change handling from a malicious peer using header and body fields, ancestry claims, seal bytes, validator ordering, and packet timing and make `Round` apply a prior round decision to a new block context, causing the invariant that round-scoped consensus messages must never be reusable across heights or rounds to fail and leading to Unauthorized transaction?

## Target
- File/function: consensus/engine/sealer.go:93 (Round)
- Entrypoint: prepare, preprepare, commit, or round-change handling from a malicious peer
- Attacker controls: header and body fields, ancestry claims, seal bytes, validator ordering, and packet timing
- Exploit idea: make `Round` apply a prior round decision to a new block context
- Invariant to test: round-scoped consensus messages must never be reusable across heights or rounds
- Expected Immunefi impact: Unauthorized transaction
- Fast validation: replay old consensus messages against new rounds and assert they cannot influence block acceptance
