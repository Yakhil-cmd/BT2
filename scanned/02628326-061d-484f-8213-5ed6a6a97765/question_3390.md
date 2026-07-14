# Q3390: nft-metadata via launcherId 3390

## Question
Can an unprivileged attacker entering through the external NFT link open action in `launcherId` (packages/gui/src/components/signVerify/SigningEntityNFT.tsx) control objectionable-content flags and hidden NFT state with a cached permission entry and drive the sequence preview -> mutate controlled state -> confirm so the GUI would trigger an unsafe external/open/download action from NFT metadata, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/signVerify/SigningEntityNFT.tsx` / `launcherId`
- Entrypoint: external NFT link open action
- Attacker controls: objectionable-content flags and hidden NFT state; with a cached permission entry
- Exploit idea: trigger an unsafe external/open/download action from NFT metadata
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
