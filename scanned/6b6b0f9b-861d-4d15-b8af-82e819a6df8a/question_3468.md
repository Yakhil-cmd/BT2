# Q3468: nft-metadata via useNFTImageFittingMode 3468

## Question
Can an unprivileged attacker entering through the NFT preview dialog in `useNFTImageFittingMode` (packages/gui/src/hooks/useNFTImageFittingMode.tsx) control HTML/SVG/media content rendered in preview through a batch of rapid user-accessible actions and drive the sequence load persisted state -> render approval -> execute command so the GUI would persist a spoofed NFT identity or DID binding after metadata refresh, violating the invariant that untrusted metadata must not gain execution or approval authority, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/hooks/useNFTImageFittingMode.tsx` / `useNFTImageFittingMode`
- Entrypoint: NFT preview dialog
- Attacker controls: HTML/SVG/media content rendered in preview; through a batch of rapid user-accessible actions
- Exploit idea: persist a spoofed NFT identity or DID binding after metadata refresh
- Invariant to test: untrusted metadata must not gain execution or approval authority
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
