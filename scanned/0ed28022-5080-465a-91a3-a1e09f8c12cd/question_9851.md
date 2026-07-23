# Q9851: ToVoteData cross-module rewind mismatch

## Question
Can an unprivileged attacker reach `ToVoteData` through rewind, blockstate, or transition rollback path across kaiax modules using governance bytes, system-transition calldata, reward or staking edge state, counters, and header metadata and make `ToVoteData` roll back one module while leaving another module on the post-reorg state, causing the invariant that every protected system module must rewind to the exact same canonical height and state root to fail and leading to Violation of tokenomics?

## Target
- File/function: kaiax/gov/headergov/vote.go:108 (ToVoteData)
- Entrypoint: rewind, blockstate, or transition rollback path across kaiax modules
- Attacker controls: governance bytes, system-transition calldata, reward or staking edge state, counters, and header metadata
- Exploit idea: make `ToVoteData` roll back one module while leaving another module on the post-reorg state
- Invariant to test: every protected system module must rewind to the exact same canonical height and state root
- Expected Immunefi impact: Violation of tokenomics
- Fast validation: trigger a local reorg across reward, staking, and gov modules and assert every module rewinds to identical canonical state
