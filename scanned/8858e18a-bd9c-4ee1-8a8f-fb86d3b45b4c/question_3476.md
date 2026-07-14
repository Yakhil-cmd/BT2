# Q3476: offers via if 3476

## Question
Can an unprivileged attacker entering through the incoming offer notification open flow in `if` (packages/gui/src/hooks/useOfferBuilderContext.ts) control offer bytes whose summary differs from displayed builder data after canceling and reopening the dialog and drive the sequence download or render content -> trigger linked wallet action so the GUI would resolve a remote offer to stale data after the preview step, violating the invariant that previewed offered/requested assets, royalties, fees, tradeId, and expiration must equal the payload sent to wallet RPC, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/hooks/useOfferBuilderContext.ts` / `if`
- Entrypoint: incoming offer notification open flow
- Attacker controls: offer bytes whose summary differs from displayed builder data; after canceling and reopening the dialog
- Exploit idea: resolve a remote offer to stale data after the preview step
- Invariant to test: previewed offered/requested assets, royalties, fees, tradeId, and expiration must equal the payload sent to wallet RPC
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
