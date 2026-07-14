# Q155: nft-metadata via NFTCard 155

## Question
Can an unprivileged attacker entering through the external NFT link open action in `NFTCard` (packages/gui/src/components/nfts/NFTCard.tsx) control filename and MIME/type mismatch during download with conflicting localStorage preferences and drive the sequence load persisted state -> render approval -> execute command so the GUI would confuse NFT id, launcher id, and wallet id when moving/transferring assets, violating the invariant that metadata refreshes must not overwrite identity-critical state with spoofed values, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/NFTCard.tsx` / `NFTCard`
- Entrypoint: external NFT link open action
- Attacker controls: filename and MIME/type mismatch during download; with conflicting localStorage preferences
- Exploit idea: confuse NFT id, launcher id, and wallet id when moving/transferring assets
- Invariant to test: metadata refreshes must not overwrite identity-critical state with spoofed values
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
