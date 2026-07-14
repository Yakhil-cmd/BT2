# Q2451: offers via defaultValues 2451

## Question
Can an unprivileged attacker entering through the incoming offer notification open flow in `defaultValues` (packages/gui/src/components/offers2/utils/defaultValues.ts) control remote offer URL response that changes between preview and acceptance with hidden Unicode characters and drive the sequence import -> parse -> preview -> submit so the GUI would resolve a remote offer to stale data after the preview step, violating the invariant that previewed offered/requested assets, royalties, fees, tradeId, and expiration must equal the payload sent to wallet RPC, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/components/offers2/utils/defaultValues.ts` / `defaultValues`
- Entrypoint: incoming offer notification open flow
- Attacker controls: remote offer URL response that changes between preview and acceptance; with hidden Unicode characters
- Exploit idea: resolve a remote offer to stale data after the preview step
- Invariant to test: previewed offered/requested assets, royalties, fees, tradeId, and expiration must equal the payload sent to wallet RPC
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
