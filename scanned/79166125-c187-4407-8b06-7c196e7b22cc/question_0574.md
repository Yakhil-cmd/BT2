# Q574: nft-metadata via MultipleDownloadDialog 574

## Question
Can an unprivileged attacker entering through the multiple NFT download action in `MultipleDownloadDialog` (packages/gui/src/components/nfts/MultipleDownloadDialog.tsx) control filename and MIME/type mismatch during download with a cached permission entry and drive the sequence validate input -> normalize payload -> call RPC so the GUI would bypass objectionable-content hiding for active content that can solicit approvals, violating the invariant that untrusted metadata must not gain execution or approval authority, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/MultipleDownloadDialog.tsx` / `MultipleDownloadDialog`
- Entrypoint: multiple NFT download action
- Attacker controls: filename and MIME/type mismatch during download; with a cached permission entry
- Exploit idea: bypass objectionable-content hiding for active content that can solicit approvals
- Invariant to test: untrusted metadata must not gain execution or approval authority
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
