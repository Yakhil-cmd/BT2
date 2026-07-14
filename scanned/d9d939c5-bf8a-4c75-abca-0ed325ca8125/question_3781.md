# Q3781: offers via handleOpen 3781

## Question
Can an unprivileged attacker entering through the incoming offer notification open flow in `handleOpen` (packages/gui/src/components/offers2/OfferBuilderImport.tsx) control offer bytes whose summary differs from displayed builder data after a profile switch and drive the sequence preview -> mutate controlled state -> confirm so the GUI would confuse DataLayer and wallet offer summaries so the wrong accept path is used, violating the invariant that offer source changes must invalidate cached summaries before acceptance, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/components/offers2/OfferBuilderImport.tsx` / `handleOpen`
- Entrypoint: incoming offer notification open flow
- Attacker controls: offer bytes whose summary differs from displayed builder data; after a profile switch
- Exploit idea: confuse DataLayer and wallet offer summaries so the wrong accept path is used
- Invariant to test: offer source changes must invalidate cached summaries before acceptance
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: mock remote fetch responses before and after preview and assert the submit path revalidates identity-critical fields
