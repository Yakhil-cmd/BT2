# Q1511: nft-metadata via getNFTInbox 1511

## Question
Can an unprivileged attacker entering through the NFT preview dialog in `getNFTInbox` (packages/gui/src/components/nfts/utils.ts) control objectionable-content flags and hidden NFT state after a network switch and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would bypass objectionable-content hiding for active content that can solicit approvals, violating the invariant that untrusted metadata must not gain execution or approval authority, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/utils.ts` / `getNFTInbox`
- Entrypoint: NFT preview dialog
- Attacker controls: objectionable-content flags and hidden NFT state; after a network switch
- Exploit idea: bypass objectionable-content hiding for active content that can solicit approvals
- Invariant to test: untrusted metadata must not gain execution or approval authority
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
