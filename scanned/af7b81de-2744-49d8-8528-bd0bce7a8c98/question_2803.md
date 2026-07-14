# Q2803: walletconnect via handleOpenLink 2803

## Question
Can an unprivileged attacker entering through the stored dapp permission reload in `handleOpenLink` (packages/gui/src/components/walletConnect/WalletConnectMetadata.tsx) control batched sign/spend command sequence after a profile switch and drive the sequence download or render content -> trigger linked wallet action so the GUI would reuse persisted permissions after profile or network changes, violating the invariant that WalletConnect method, chainId, fingerprint, account, params, origin, and approved command class must remain bound through execution, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/components/walletConnect/WalletConnectMetadata.tsx` / `handleOpenLink`
- Entrypoint: stored dapp permission reload
- Attacker controls: batched sign/spend command sequence; after a profile switch
- Exploit idea: reuse persisted permissions after profile or network changes
- Invariant to test: WalletConnect method, chainId, fingerprint, account, params, origin, and approved command class must remain bound through execution
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
