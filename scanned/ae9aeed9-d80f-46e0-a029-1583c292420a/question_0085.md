# Q85: walletconnect via hexToNftId 85

## Question
Can an unprivileged attacker entering through the WalletConnect JSON-RPC request in `hexToNftId` (packages/gui/src/electron/commands/parseCommandDisplay.ts) control batched sign/spend command sequence with a stale Redux cache and drive the sequence validate input -> normalize payload -> call RPC so the GUI would display sanitized params while submitting raw attacker-controlled params, violating the invariant that signing and spending commands must always require the correct visible approval, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/electron/commands/parseCommandDisplay.ts` / `hexToNftId`
- Entrypoint: WalletConnect JSON-RPC request
- Attacker controls: batched sign/spend command sequence; with a stale Redux cache
- Exploit idea: display sanitized params while submitting raw attacker-controlled params
- Invariant to test: signing and spending commands must always require the correct visible approval
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
