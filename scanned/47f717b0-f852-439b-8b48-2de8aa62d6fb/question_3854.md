# Q3854: walletconnect via memoizedMetadata 3854

## Question
Can an unprivileged attacker entering through the WalletConnect JSON-RPC request in `memoizedMetadata` (packages/gui/src/hooks/useWalletConnectClient.ts) control method name and params with casing or namespace ambiguity with a redirected remote resource and drive the sequence connect -> approve -> switch context -> execute so the GUI would display sanitized params while submitting raw attacker-controlled params, violating the invariant that stored permissions must be invalidated on profile/network changes, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/hooks/useWalletConnectClient.ts` / `memoizedMetadata`
- Entrypoint: WalletConnect JSON-RPC request
- Attacker controls: method name and params with casing or namespace ambiguity; with a redirected remote resource
- Exploit idea: display sanitized params while submitting raw attacker-controlled params
- Invariant to test: stored permissions must be invalidated on profile/network changes
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
