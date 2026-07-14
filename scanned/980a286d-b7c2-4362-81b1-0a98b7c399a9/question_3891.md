# Q3891: nft-metadata via NFTCard 3891

## Question
Can an unprivileged attacker entering through the on-demand NFT data provider in `NFTCard` (packages/gui/src/components/nfts/NFTCard.tsx) control filename and MIME/type mismatch during download after a failed RPC response and drive the sequence validate input -> normalize payload -> call RPC so the GUI would persist a spoofed NFT identity or DID binding after metadata refresh, violating the invariant that untrusted metadata must not gain execution or approval authority, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/NFTCard.tsx` / `NFTCard`
- Entrypoint: on-demand NFT data provider
- Attacker controls: filename and MIME/type mismatch during download; after a failed RPC response
- Exploit idea: persist a spoofed NFT identity or DID binding after metadata refresh
- Invariant to test: untrusted metadata must not gain execution or approval authority
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
