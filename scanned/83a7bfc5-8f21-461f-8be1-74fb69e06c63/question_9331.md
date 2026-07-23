# Q9331: MaxRound peer delivery race

## Question
Can an unprivileged attacker reach `MaxRound` through parallel peer delivery of headers, bodies, and consensus data using header and body fields, ancestry claims, seal bytes, validator ordering, and packet timing and make `MaxRound` persist partially validated consensus data under a race between peers, causing the invariant that partial peer data must never become durable or trusted before full validation completes to fail and leading to Balance manipulation?

## Target
- File/function: consensus/istanbul/core/roundchange.go:206 (MaxRound)
- Entrypoint: parallel peer delivery of headers, bodies, and consensus data
- Attacker controls: header and body fields, ancestry claims, seal bytes, validator ordering, and packet timing
- Exploit idea: make `MaxRound` persist partially validated consensus data under a race between peers
- Invariant to test: partial peer data must never become durable or trusted before full validation completes
- Expected Immunefi impact: Balance manipulation
- Fast validation: drive competing peers that deliver inconsistent fragments and assert no durable state changes occur before full validation
