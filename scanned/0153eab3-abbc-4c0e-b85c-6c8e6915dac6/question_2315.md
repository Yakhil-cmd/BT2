# Q2315: walletconnect via dispatchPairRequest 2315

## Question
Can an unprivileged attacker entering through the pairing URI/import flow in `dispatchPairRequest` (packages/gui/src/electron/utils/dispatchPairRequest.ts) control method name and params with casing or namespace ambiguity with hidden Unicode characters and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would classify a spend/sign command as a harmless balance command, violating the invariant that signing and spending commands must always require the correct visible approval, leading to Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion?

## Target
- File/function: `packages/gui/src/electron/utils/dispatchPairRequest.ts` / `dispatchPairRequest`
- Entrypoint: pairing URI/import flow
- Attacker controls: method name and params with casing or namespace ambiguity; with hidden Unicode characters
- Exploit idea: classify a spend/sign command as a harmless balance command
- Invariant to test: signing and spending commands must always require the correct visible approval
- Expected Immunefi impact: Critical: unauthorized signing or spend through WalletConnect; High: approval bypass or signing-context confusion
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
