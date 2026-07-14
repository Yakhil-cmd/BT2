# Q1479: nft-metadata via NFTAttribute 1479

## Question
Can an unprivileged attacker entering through the multiple NFT download action in `NFTAttribute` (packages/api/src/@types/NFTAttribute.ts) control objectionable-content flags and hidden NFT state after a failed RPC response and drive the sequence open notification -> resolve details -> execute so the GUI would confuse NFT id, launcher id, and wallet id when moving/transferring assets, violating the invariant that untrusted metadata must not gain execution or approval authority, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/api/src/@types/NFTAttribute.ts` / `NFTAttribute`
- Entrypoint: multiple NFT download action
- Attacker controls: objectionable-content flags and hidden NFT state; after a failed RPC response
- Exploit idea: confuse NFT id, launcher id, and wallet id when moving/transferring assets
- Invariant to test: untrusted metadata must not gain execution or approval authority
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
