# Q935: walletconnect via handleOpenLink 935

## Question
Can an unprivileged attacker entering through the WalletConnect JSON-RPC request in `handleOpenLink` (packages/gui/src/components/walletConnect/WalletConnectMetadata.tsx) control method name and params with casing or namespace ambiguity with precision-boundary values and drive the sequence open notification -> resolve details -> execute so the GUI would display sanitized params while submitting raw attacker-controlled params, violating the invariant that WalletConnect method, chainId, fingerprint, account, params, origin, and approved command class must remain bound through execution, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/components/walletConnect/WalletConnectMetadata.tsx` / `handleOpenLink`
- Entrypoint: WalletConnect JSON-RPC request
- Attacker controls: method name and params with casing or namespace ambiguity; with precision-boundary values
- Exploit idea: display sanitized params while submitting raw attacker-controlled params
- Invariant to test: WalletConnect method, chainId, fingerprint, account, params, origin, and approved command class must remain bound through execution
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
