# Q154: nft-metadata via NFTCard 154

## Question
Can an unprivileged attacker entering through the multiple NFT download action in `NFTCard` (packages/gui/src/components/nfts/NFTCard.tsx) control filename and MIME/type mismatch during download with case-normalized identifiers and drive the sequence load persisted state -> render approval -> execute command so the GUI would confuse NFT id, launcher id, and wallet id when moving/transferring assets, violating the invariant that untrusted metadata must not gain execution or approval authority, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/NFTCard.tsx` / `NFTCard`
- Entrypoint: multiple NFT download action
- Attacker controls: filename and MIME/type mismatch during download; with case-normalized identifiers
- Exploit idea: confuse NFT id, launcher id, and wallet id when moving/transferring assets
- Invariant to test: untrusted metadata must not gain execution or approval authority
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
