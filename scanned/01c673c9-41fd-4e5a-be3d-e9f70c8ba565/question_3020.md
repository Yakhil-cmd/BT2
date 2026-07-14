# Q3020: offers via StyledHeaderBox 3020

## Question
Can an unprivileged attacker entering through the offer accept/cancel confirmation flow in `StyledHeaderBox` (packages/gui/src/components/offers/OfferHeader.tsx) control NFT/CAT identifiers with duplicate or ambiguous entries with reordered RPC events and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would resolve a remote offer to stale data after the preview step, violating the invariant that secure cancellation and ownership checks must remain bound to the selected trade, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/components/offers/OfferHeader.tsx` / `StyledHeaderBox`
- Entrypoint: offer accept/cancel confirmation flow
- Attacker controls: NFT/CAT identifiers with duplicate or ambiguous entries; with reordered RPC events
- Exploit idea: resolve a remote offer to stale data after the preview step
- Invariant to test: secure cancellation and ownership checks must remain bound to the selected trade
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
