# Q555: rpc-state via SignagePoint 555

## Question
Can an unprivileged attacker entering through the service command response correlation in `SignagePoint` (packages/api/src/@types/SignagePoint.ts) control out-of-order event and query responses with case-normalized identifiers and drive the sequence select -> edit backing object -> submit so the GUI would mis-handle precision for mojos, royalties, or fees in state, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api/src/@types/SignagePoint.ts` / `SignagePoint`
- Entrypoint: service command response correlation
- Attacker controls: out-of-order event and query responses; with case-normalized identifiers
- Exploit idea: mis-handle precision for mojos, royalties, or fees in state
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
