# Q2443: nft-metadata via FilterPill 2443

## Question
Can an unprivileged attacker entering through the multiple NFT download action in `FilterPill` (packages/gui/src/components/nfts/gallery/FilterPill.tsx) control objectionable-content flags and hidden NFT state with a delayed metadata fetch and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would bypass objectionable-content hiding for active content that can solicit approvals, violating the invariant that untrusted metadata must not gain execution or approval authority, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/gallery/FilterPill.tsx` / `FilterPill`
- Entrypoint: multiple NFT download action
- Attacker controls: objectionable-content flags and hidden NFT state; with a delayed metadata fetch
- Exploit idea: bypass objectionable-content hiding for active content that can solicit approvals
- Invariant to test: untrusted metadata must not gain execution or approval authority
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
