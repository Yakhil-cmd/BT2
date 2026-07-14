# Q4000: offers via displayValue 4000

## Question
Can an unprivileged attacker entering through the offer URL fetch/import flow in `displayValue` (packages/gui/src/components/offers2/OfferBuilderValue.tsx) control offer bytes whose summary differs from displayed builder data with reordered RPC events and drive the sequence download or render content -> trigger linked wallet action so the GUI would bypass royalty or fee accounting in the displayed confirmation, violating the invariant that offer source changes must invalidate cached summaries before acceptance, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/components/offers2/OfferBuilderValue.tsx` / `displayValue`
- Entrypoint: offer URL fetch/import flow
- Attacker controls: offer bytes whose summary differs from displayed builder data; with reordered RPC events
- Exploit idea: bypass royalty or fee accounting in the displayed confirmation
- Invariant to test: offer source changes must invalidate cached summaries before acceptance
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
