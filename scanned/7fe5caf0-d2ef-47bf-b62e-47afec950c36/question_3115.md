# Q3115: walletconnect via if 3115

## Question
Can an unprivileged attacker entering through the WalletConnect session proposal in `if` (packages/gui/src/electron/commands/humanizeDappCommandName.ts) control method name and params with casing or namespace ambiguity with hidden Unicode characters and drive the sequence import -> parse -> preview -> submit so the GUI would display sanitized params while submitting raw attacker-controlled params, violating the invariant that stored permissions must be invalidated on profile/network changes, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/electron/commands/humanizeDappCommandName.ts` / `if`
- Entrypoint: WalletConnect session proposal
- Attacker controls: method name and params with casing or namespace ambiguity; with hidden Unicode characters
- Exploit idea: display sanitized params while submitting raw attacker-controlled params
- Invariant to test: stored permissions must be invalidated on profile/network changes
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
