# Q276: offers via cols 276

## Question
Can an unprivileged attacker entering through the incoming offer notification open flow in `cols` (packages/gui/src/components/offers2/OfferIncomingTable.tsx) control offer bytes whose summary differs from displayed builder data during a pending modal confirmation and drive the sequence open notification -> resolve details -> execute so the GUI would resolve a remote offer to stale data after the preview step, violating the invariant that offer source changes must invalidate cached summaries before acceptance, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/components/offers2/OfferIncomingTable.tsx` / `cols`
- Entrypoint: incoming offer notification open flow
- Attacker controls: offer bytes whose summary differs from displayed builder data; during a pending modal confirmation
- Exploit idea: resolve a remote offer to stale data after the preview step
- Invariant to test: offer source changes must invalidate cached summaries before acceptance
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
