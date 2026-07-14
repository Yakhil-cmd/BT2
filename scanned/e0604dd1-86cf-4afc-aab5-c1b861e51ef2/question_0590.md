# Q590: walletconnect via formatMojoXch 590

## Question
Can an unprivileged attacker entering through the WalletConnect session proposal in `formatMojoXch` (packages/gui/src/electron/commands/humanizeParamValue.ts) control previously granted bypass permission combined with profile switch after a failed RPC response and drive the sequence load persisted state -> render approval -> execute command so the GUI would display sanitized params while submitting raw attacker-controlled params, violating the invariant that signing and spending commands must always require the correct visible approval, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/electron/commands/humanizeParamValue.ts` / `formatMojoXch`
- Entrypoint: WalletConnect session proposal
- Attacker controls: previously granted bypass permission combined with profile switch; after a failed RPC response
- Exploit idea: display sanitized params while submitting raw attacker-controlled params
- Invariant to test: signing and spending commands must always require the correct visible approval
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
