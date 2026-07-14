# Q168: nft-metadata via NFTProgressBar 168

## Question
Can an unprivileged attacker entering through the external NFT link open action in `NFTProgressBar` (packages/gui/src/components/nfts/NFTProgressBar.tsx) control objectionable-content flags and hidden NFT state after a network switch and drive the sequence validate input -> normalize payload -> call RPC so the GUI would confuse NFT id, launcher id, and wallet id when moving/transferring assets, violating the invariant that untrusted metadata must not gain execution or approval authority, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/NFTProgressBar.tsx` / `NFTProgressBar`
- Entrypoint: external NFT link open action
- Attacker controls: objectionable-content flags and hidden NFT state; after a network switch
- Exploit idea: confuse NFT id, launcher id, and wallet id when moving/transferring assets
- Invariant to test: untrusted metadata must not gain execution or approval authority
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
