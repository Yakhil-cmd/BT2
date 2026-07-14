# Q3301: walletconnect via if 3301

## Question
Can an unprivileged attacker entering through the dapp command permission prompt in `if` (packages/gui/src/hooks/useWalletConnect.ts) control chainId/account/fingerprint mismatch with a duplicate identifier and drive the sequence open notification -> resolve details -> execute so the GUI would reuse persisted permissions after profile or network changes, violating the invariant that stored permissions must be invalidated on profile/network changes, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/hooks/useWalletConnect.ts` / `if`
- Entrypoint: dapp command permission prompt
- Attacker controls: chainId/account/fingerprint mismatch; with a duplicate identifier
- Exploit idea: reuse persisted permissions after profile or network changes
- Invariant to test: stored permissions must be invalidated on profile/network changes
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
