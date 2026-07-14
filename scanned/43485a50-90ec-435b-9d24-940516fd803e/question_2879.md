# Q2879: nft-metadata via nftGetInfo 2879

## Question
Can an unprivileged attacker entering through the NFT preview dialog in `nftGetInfo` (packages/gui/src/electron/api/nftGetInfo.ts) control objectionable-content flags and hidden NFT state with a stale Redux cache and drive the sequence import -> parse -> preview -> submit so the GUI would bypass objectionable-content hiding for active content that can solicit approvals, violating the invariant that untrusted metadata must not gain execution or approval authority, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/electron/api/nftGetInfo.ts` / `nftGetInfo`
- Entrypoint: NFT preview dialog
- Attacker controls: objectionable-content flags and hidden NFT state; with a stale Redux cache
- Exploit idea: bypass objectionable-content hiding for active content that can solicit approvals
- Invariant to test: untrusted metadata must not gain execution or approval authority
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
