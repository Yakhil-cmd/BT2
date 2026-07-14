# Q3584: offers via RoyaltyCalculationRoyaltyAsset 3584

## Question
Can an unprivileged attacker entering through the crafted offer file import in `RoyaltyCalculationRoyaltyAsset` (packages/api/src/@types/RoyaltyCalculationRoyaltyAsset.ts) control remote offer URL response that changes between preview and acceptance with a redirected remote resource and drive the sequence open notification -> resolve details -> execute so the GUI would resolve a remote offer to stale data after the preview step, violating the invariant that offer source changes must invalidate cached summaries before acceptance, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/api/src/@types/RoyaltyCalculationRoyaltyAsset.ts` / `RoyaltyCalculationRoyaltyAsset`
- Entrypoint: crafted offer file import
- Attacker controls: remote offer URL response that changes between preview and acceptance; with a redirected remote resource
- Exploit idea: resolve a remote offer to stale data after the preview step
- Invariant to test: offer source changes must invalidate cached summaries before acceptance
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
