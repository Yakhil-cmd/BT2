# Q2997: nft-metadata via unsubscribeDemand 2997

## Question
Can an unprivileged attacker entering through the external NFT link open action in `unsubscribeDemand` (packages/gui/src/components/nfts/provider/NFTProvider.tsx) control metadata URI list with mixed schemes and redirects with case-normalized identifiers and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would trigger an unsafe external/open/download action from NFT metadata, violating the invariant that untrusted metadata must not gain execution or approval authority, leading to High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing?

## Target
- File/function: `packages/gui/src/components/nfts/provider/NFTProvider.tsx` / `unsubscribeDemand`
- Entrypoint: external NFT link open action
- Attacker controls: metadata URI list with mixed schemes and redirects; with case-normalized identifiers
- Exploit idea: trigger an unsafe external/open/download action from NFT metadata
- Invariant to test: untrusted metadata must not gain execution or approval authority
- Expected Immunefi impact: High: unsafe trust of NFT metadata/content causing wrong-asset approval, unsafe external content handling, or signing-context spoofing
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
