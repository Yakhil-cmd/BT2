### Title
CR-CAT Restriction Spoofing via Untrusted Offer Payload — (`packages/gui/src/components/offers2/OfferBuilderToken.tsx`, `packages/gui/src/util/offerToOfferBuilderData.ts`)

---

### Summary

The offer import flow trusts the `also` field of the offer's `infos` payload to display CR-CAT credential restrictions and authorized providers. No cross-reference with the wallet's actual on-chain metadata is performed. An attacker who crafts an offer can cause the GUI to display arbitrary flags and provider identities for any CAT, deceiving the user into approving an offer under false pretenses about the token's credential requirements.

---

### Finding Description

**Step 1 — Attacker-controlled entrypoint**

The offer summary's `infos` map is populated by the Chia node parsing the offer blob. Because CR-CAT restrictions are encoded in the puzzle (which is part of the offer blob), an attacker who crafts an offer can include a puzzle that encodes arbitrary `authorizedProviders` and `flags` values. The node faithfully reflects these back in the `infos[assetId].also` field of the offer summary.

**Step 2 — `offerToOfferBuilderData` maps payload directly to form state**

`extractCrCatData` in `offerToOfferBuilderData.ts` performs only one check — `info.also.type !== 'credential restricted'` — which the attacker trivially satisfies. It then copies `flags` and `authorizedProviders` verbatim from the offer payload into the form state `crCat` field: [1](#0-0) 

**Step 3 — `OfferBuilderToken` renders the attacker-controlled `crCat` from form state**

`useWatch` returns the form state value (populated from the offer payload). If `crCat` is truthy, the component renders `CrCatFlags` and `CrCatAuthorizedProviders` directly from it, with no wallet lookup: [2](#0-1) 

**Step 4 — `CrCatFlags` uses attacker-controlled `authorizedProviders` for VC validation display**

`CrCatFlags` checks whether the user holds a VC from the `restrictions.authorizedProviders` list — but that list is the attacker-controlled one. The rendered flag chips and their "valid/invalid" status are therefore based on attacker-supplied data: [3](#0-2) 

**Step 5 — Contrast with the legitimate wallet view**

`WalletCardCRCatRestrictions` — the component used for the actual wallet detail page — correctly fetches restrictions from `wallet.authorizedProviders` and `wallet.flagsNeeded` via `useGetWalletsQuery`, i.e., from on-chain wallet metadata: [4](#0-3) 

The offer builder has no equivalent lookup. There is no guard that cross-references the displayed `crCat` data against the wallet record for the matching `assetId`.

---

### Impact Explanation

An attacker can:

1. Make a **plain CAT appear as a CR-CAT** with specific credential requirements (e.g., "kyc_verified"), causing the user to believe they are receiving a regulated/credentialed token when they are not.
2. Make a **CR-CAT appear to have different restrictions** than it actually has on-chain — e.g., showing a permissive provider list when the real token requires a different, stricter one.
3. Manipulate the **VC validity indicator** in `CrCatFlags` by listing a provider the user happens to hold a VC from, making the offer appear fully credentialed and ready to accept.

The user approves the offer based on spoofed credential restriction information, violating the invariant that CR-CAT restriction display must be sourced from on-chain wallet metadata.

This fits the allowed High impact: *"Corruption, spoofing, or unsafe trust of … offer … state that causes a user to … display the wrong asset, identity, amount, destination, or status."*

---

### Likelihood Explanation

- Requires only crafting a valid offer file with a modified puzzle encoding arbitrary CR-CAT restrictions — no privileged access, no key material, no local compromise.
- The victim only needs to import the offer (via file, QR, or URL) and view the offer builder screen.
- The attack is fully reproducible locally.

---

### Recommendation

In `OfferBuilderToken`, after resolving the wallet by `assetId`, cross-reference the displayed CR-CAT data against the wallet's actual `authorizedProviders` and `flagsNeeded` fields (as `WalletCardCRCatRestrictions` does), rather than rendering the `crCat` object from form state. If the wallet is unknown (no matching wallet record), either suppress the CR-CAT restriction display entirely or show an explicit warning that the restrictions are unverified and sourced from the offer payload.

---

### Proof of Concept

1. Craft an offer where `infos[<assetId>]` has `type: 'CAT'` and `also: { type: 'credential restricted', authorizedProviders: ['<attacker_provider_hash>'], flags: ['kyc_verified'], proofsChecker: '...' }`, where `<assetId>` is the asset ID of a plain CAT the attacker is offering.
2. Import the offer into the Chia GUI via the standard offer import flow.
3. Observe that the offer builder displays "CAT credential restrictions: kyc_verified" and "Authorized providers: [attacker_provider_hash]" for the token.
4. Confirm that the wallet record for `<assetId>` has no such restrictions (or does not exist as a CR-CAT wallet).
5. The displayed restrictions match the crafted offer payload, not the wallet's on-chain metadata — confirming the spoofing.

### Citations

**File:** packages/gui/src/util/offerToOfferBuilderData.ts (L93-101)
```typescript
function extractCrCatData(info: OfferSummaryCATInfo) {
  if (!info.also) return undefined;
  if (info.also.type !== 'credential restricted') return undefined;
  const { flags, authorizedProviders } = info.also;
  return {
    flags,
    authorizedProviders,
  };
}
```

**File:** packages/gui/src/components/offers2/OfferBuilderToken.tsx (L56-67)
```typescript
          {crCat && (
            <Flex gap={1} flexDirection="column" sx={{ mt: 2 }}>
              <Typography variant="body1">
                <Trans>CAT credential restrictions</Trans>:
              </Typography>
              <CrCatFlags restrictions={crCat} />
              <Typography variant="body1">
                <Trans>Authorized providers</Trans>:
              </Typography>
              <CrCatAuthorizedProviders authorizedProviders={crCat.authorizedProviders} />
            </Flex>
          )}
```

**File:** packages/wallets/src/components/crCat/CrCatFlags.tsx (L43-48)
```typescript
                if (
                  restrictions.authorizedProviders
                    .map((provider) => (provider.startsWith('0x') ? provider : `0x${provider}`))
                    .includes(vcRecord.vc.proofProvider)
                ) {
                  toReturn.push(foundFlag.flag);
```

**File:** packages/wallets/src/components/card/WalletCardCRCatRestrictions.tsx (L24-37)
```typescript
  const restrictions = useMemo(() => {
    if (isGetWalletsLoading || !wallets) {
      return undefined;
    }

    const wallet = wallets.find((item) => item.id === walletId);
    if (!wallet) {
      return undefined;
    }
    return {
      authorizedProviders: wallet.authorizedProviders || [],
      flags: wallet.flagsNeeded || [],
    };
  }, [isGetWalletsLoading, walletId, wallets]);
```
