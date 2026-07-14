# Q2570: offers via if 2570

## Question
Can an unprivileged attacker entering through the offer URL fetch/import flow in `if` (packages/gui/src/util/resolveOfferInfo.tsx) control conflicting offer IDs and secure-cancel flags during a pending modal confirmation and drive the sequence download or render content -> trigger linked wallet action so the GUI would make the user approve one offer summary while the RPC accepts different offered/requested assets, violating the invariant that previewed offered/requested assets, royalties, fees, tradeId, and expiration must equal the payload sent to wallet RPC, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/util/resolveOfferInfo.tsx` / `if`
- Entrypoint: offer URL fetch/import flow
- Attacker controls: conflicting offer IDs and secure-cancel flags; during a pending modal confirmation
- Exploit idea: make the user approve one offer summary while the RPC accepts different offered/requested assets
- Invariant to test: previewed offered/requested assets, royalties, fees, tradeId, and expiration must equal the payload sent to wallet RPC
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
