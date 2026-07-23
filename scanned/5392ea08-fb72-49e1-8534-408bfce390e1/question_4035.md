# Q4035: contractGetAllParamsAtFromAddr reward or supply accounting split

## Question
Can an unprivileged attacker reach `contractGetAllParamsAtFromAddr` through system-transition execution that distributes rewards or mutates total supply using governance bytes, system-transition calldata, reward or staking edge state, counters, and header metadata and make `contractGetAllParamsAtFromAddr` credit balances and total supply inconsistently, causing the invariant that reward recipients, burned amounts, and total supply must reconcile exactly after each transition to fail and leading to Violation of tokenomics?

## Target
- File/function: kaiax/gov/contractgov/impl/getter.go:55 (contractGetAllParamsAtFromAddr)
- Entrypoint: system-transition execution that distributes rewards or mutates total supply
- Attacker controls: governance bytes, system-transition calldata, reward or staking edge state, counters, and header metadata
- Exploit idea: make `contractGetAllParamsAtFromAddr` credit balances and total supply inconsistently
- Invariant to test: reward recipients, burned amounts, and total supply must reconcile exactly after each transition
- Expected Immunefi impact: Violation of tokenomics
- Fast validation: execute a crafted transition and reconcile every reward delta against the post-transition supply accounting
