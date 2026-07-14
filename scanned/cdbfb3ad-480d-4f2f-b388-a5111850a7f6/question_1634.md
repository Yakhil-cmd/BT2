# Q1634: nft-metadata via normalizeUrl 1634

## Question
Can an unprivileged attacker entering through the NFT metadata fetch/render flow in `normalizeUrl` (packages/gui/src/util/normalizeUrl.ts) control content hash/status fields that change across fetches with case-normalized identifiers and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would bypass objectionable-content hiding for active content that can solicit approvals, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/util/normalizeUrl.ts` / `normalizeUrl`
- Entrypoint: NFT metadata fetch/render flow
- Attacker controls: content hash/status fields that change across fetches; with case-normalized identifiers
- Exploit idea: bypass objectionable-content hiding for active content that can solicit approvals
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
