# Q2189: handleVRankCandidateMsg cross-module validation gap

## Question
Can an unprivileged attacker reach `handleVRankCandidateMsg` through block validation path that also touches reward, valset, or header-gov logic using header and body fields, ancestry claims, seal bytes, validator ordering, and packet timing and make `handleVRankCandidateMsg` pass consensus validation while smuggling an inconsistent system transition, causing the invariant that consensus validation and system-transition validation must agree on the exact accepted header state to fail and leading to Violation of tokenomics?

## Target
- File/function: node/cn/handler.go:1254 (handleVRankCandidateMsg)
- Entrypoint: block validation path that also touches reward, valset, or header-gov logic
- Attacker controls: header and body fields, ancestry claims, seal bytes, validator ordering, and packet timing
- Exploit idea: make `handleVRankCandidateMsg` pass consensus validation while smuggling an inconsistent system transition
- Invariant to test: consensus validation and system-transition validation must agree on the exact accepted header state
- Expected Immunefi impact: Violation of tokenomics
- Fast validation: build blocks whose header metadata conflicts with embedded system transitions and assert import rejects them before state mutation
