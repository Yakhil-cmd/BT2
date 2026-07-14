# Q3380: offers via NotificationOffer 3380

## Question
Can an unprivileged attacker entering through the offer URL fetch/import flow in `NotificationOffer` (packages/gui/src/components/notification/NotificationOffer.tsx) control conflicting offer IDs and secure-cancel flags after a profile switch and drive the sequence validate input -> normalize payload -> call RPC so the GUI would cancel or accept a tradeId different from the row the user selected, violating the invariant that offer source changes must invalidate cached summaries before acceptance, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/components/notification/NotificationOffer.tsx` / `NotificationOffer`
- Entrypoint: offer URL fetch/import flow
- Attacker controls: conflicting offer IDs and secure-cancel flags; after a profile switch
- Exploit idea: cancel or accept a tradeId different from the row the user selected
- Invariant to test: offer source changes must invalidate cached summaries before acceptance
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
