# Q3890: nft-metadata via NFTCard 3890

## Question
Can an unprivileged attacker entering through the external NFT link open action in `NFTCard` (packages/gui/src/components/nfts/NFTCard.tsx) control filename and MIME/type mismatch during download after a failed RPC response and drive the sequence validate input -> normalize payload -> call RPC so the GUI would trigger an unsafe external/open/download action from NFT metadata, violating the invariant that untrusted metadata must not gain execution or approval authority, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/NFTCard.tsx` / `NFTCard`
- Entrypoint: external NFT link open action
- Attacker controls: filename and MIME/type mismatch during download; after a failed RPC response
- Exploit idea: trigger an unsafe external/open/download action from NFT metadata
- Invariant to test: untrusted metadata must not gain execution or approval authority
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
