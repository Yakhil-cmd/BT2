# Q657: nft-metadata via useFetchAndProcessMetadata 657

## Question
Can an unprivileged attacker entering through the external NFT link open action in `useFetchAndProcessMetadata` (packages/gui/src/hooks/useFetchAndProcessMetadata.ts) control objectionable-content flags and hidden NFT state with a cached permission entry and drive the sequence validate input -> normalize payload -> call RPC so the GUI would bypass objectionable-content hiding for active content that can solicit approvals, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/hooks/useFetchAndProcessMetadata.ts` / `useFetchAndProcessMetadata`
- Entrypoint: external NFT link open action
- Attacker controls: objectionable-content flags and hidden NFT state; with a cached permission entry
- Exploit idea: bypass objectionable-content hiding for active content that can solicit approvals
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
