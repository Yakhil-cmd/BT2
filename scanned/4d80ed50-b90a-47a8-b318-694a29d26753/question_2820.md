# Q2820: nft-metadata via if 2820

## Question
Can an unprivileged attacker entering through the external NFT link open action in `if` (packages/gui/src/components/nfts/NFTMoveToProfileDialog.tsx) control content hash/status fields that change across fetches after canceling and reopening the dialog and drive the sequence load persisted state -> render approval -> execute command so the GUI would persist a spoofed NFT identity or DID binding after metadata refresh, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/NFTMoveToProfileDialog.tsx` / `if`
- Entrypoint: external NFT link open action
- Attacker controls: content hash/status fields that change across fetches; after canceling and reopening the dialog
- Exploit idea: persist a spoofed NFT identity or DID binding after metadata refresh
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
