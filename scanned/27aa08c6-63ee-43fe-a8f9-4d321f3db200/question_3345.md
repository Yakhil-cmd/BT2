# Q3345: nft-metadata via DataLayerRootHash 3345

## Question
Can an unprivileged attacker entering through the external NFT link open action in `DataLayerRootHash` (packages/api/src/@types/DataLayerRootHash.ts) control content hash/status fields that change across fetches through a batch of rapid user-accessible actions and drive the sequence select -> edit backing object -> submit so the GUI would persist a spoofed NFT identity or DID binding after metadata refresh, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/api/src/@types/DataLayerRootHash.ts` / `DataLayerRootHash`
- Entrypoint: external NFT link open action
- Attacker controls: content hash/status fields that change across fetches; through a batch of rapid user-accessible actions
- Exploit idea: persist a spoofed NFT identity or DID binding after metadata refresh
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
