# Q3381: nft-metadata via if 3381

## Question
Can an unprivileged attacker entering through the multiple NFT download action in `if` (packages/gui/src/components/notification/NotificationPreviewNFT.tsx) control filename and MIME/type mismatch during download with a duplicate identifier and drive the sequence connect -> approve -> switch context -> execute so the GUI would bypass objectionable-content hiding for active content that can solicit approvals, violating the invariant that untrusted metadata must not gain execution or approval authority, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/notification/NotificationPreviewNFT.tsx` / `if`
- Entrypoint: multiple NFT download action
- Attacker controls: filename and MIME/type mismatch during download; with a duplicate identifier
- Exploit idea: bypass objectionable-content hiding for active content that can solicit approvals
- Invariant to test: untrusted metadata must not gain execution or approval authority
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
