# Q447: walletconnect via dispatchPairRequest 447

## Question
Can an unprivileged attacker entering through the WalletConnect session proposal in `dispatchPairRequest` (packages/gui/src/electron/utils/dispatchPairRequest.ts) control chainId/account/fingerprint mismatch with a redirected remote resource and drive the sequence fetch -> cache -> refresh -> submit so the GUI would display sanitized params while submitting raw attacker-controlled params, violating the invariant that signing and spending commands must always require the correct visible approval, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/electron/utils/dispatchPairRequest.ts` / `dispatchPairRequest`
- Entrypoint: WalletConnect session proposal
- Attacker controls: chainId/account/fingerprint mismatch; with a redirected remote resource
- Exploit idea: display sanitized params while submitting raw attacker-controlled params
- Invariant to test: signing and spending commands must always require the correct visible approval
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
