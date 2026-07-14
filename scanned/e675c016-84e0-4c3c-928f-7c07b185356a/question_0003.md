# Q3: walletconnect via WalletConnectMetadata 3

## Question
Can an unprivileged attacker entering through the stored dapp permission reload in `WalletConnectMetadata` (packages/gui/src/components/walletConnect/WalletConnectMetadata.tsx) control session metadata with misleading origin/icon/name fields during a pending modal confirmation and drive the sequence import -> parse -> preview -> submit so the GUI would reuse persisted permissions after profile or network changes, violating the invariant that WalletConnect method, chainId, fingerprint, account, params, origin, and approved command class must remain bound through execution, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/components/walletConnect/WalletConnectMetadata.tsx` / `WalletConnectMetadata`
- Entrypoint: stored dapp permission reload
- Attacker controls: session metadata with misleading origin/icon/name fields; during a pending modal confirmation
- Exploit idea: reuse persisted permissions after profile or network changes
- Invariant to test: WalletConnect method, chainId, fingerprint, account, params, origin, and approved command class must remain bound through execution
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
