# Q2037: nft-metadata via unsubscribeDownloadDone 2037

## Question
Can an unprivileged attacker entering through the multiple NFT download action in `unsubscribeDownloadDone` (packages/gui/src/components/nfts/NFTProgressBar.tsx) control content hash/status fields that change across fetches through a batch of rapid user-accessible actions and drive the sequence download or render content -> trigger linked wallet action so the GUI would bypass objectionable-content hiding for active content that can solicit approvals, violating the invariant that untrusted metadata must not gain execution or approval authority, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/NFTProgressBar.tsx` / `unsubscribeDownloadDone`
- Entrypoint: multiple NFT download action
- Attacker controls: content hash/status fields that change across fetches; through a batch of rapid user-accessible actions
- Exploit idea: bypass objectionable-content hiding for active content that can solicit approvals
- Invariant to test: untrusted metadata must not gain execution or approval authority
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
