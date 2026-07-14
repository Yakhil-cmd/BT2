# Q370: rpc-state via Search 370

## Question
Can an unprivileged attacker entering through the camel/snake case transform path in `Search` (packages/wallets/src/components/WalletsManageTokens.tsx) control large numeric fields near JS precision limits with hidden Unicode characters and drive the sequence select -> edit backing object -> submit so the GUI would display one balance/asset state while executing with another, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/wallets/src/components/WalletsManageTokens.tsx` / `Search`
- Entrypoint: camel/snake case transform path
- Attacker controls: large numeric fields near JS precision limits; with hidden Unicode characters
- Exploit idea: display one balance/asset state while executing with another
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
