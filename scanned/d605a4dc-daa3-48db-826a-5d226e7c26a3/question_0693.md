# Q693: nft-metadata via download 693

## Question
Can an unprivileged attacker entering through the NFT metadata fetch/render flow in `download` (packages/gui/src/util/download.ts) control filename and MIME/type mismatch during download with a cached permission entry and drive the sequence import -> parse -> preview -> submit so the GUI would trigger an unsafe external/open/download action from NFT metadata, violating the invariant that untrusted metadata must not gain execution or approval authority, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/util/download.ts` / `download`
- Entrypoint: NFT metadata fetch/render flow
- Attacker controls: filename and MIME/type mismatch during download; with a cached permission entry
- Exploit idea: trigger an unsafe external/open/download action from NFT metadata
- Invariant to test: untrusted metadata must not gain execution or approval authority
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
