Let me trace the exact code path before rendering a verdict.

**Step 1 — Import (`getVCFromLocalFile`, VCList.tsx:180-219)**

The crafted JSON is parsed and stored verbatim in localStorage under `VCsLocalStorage[fingerprint]` with `isLocal: true`. No validation of `vc.launcherId` against blockchain state occurs. [1](#0-0) 

**Step 2 — Card click navigation (VCCard.tsx:364-369)**

The local VC card's `onClick` navigates to `/dashboard/vc/${vcRecord?.vc?.launcherId || vcRecord.sha256}`. If the crafted file contains `vc.launcherId = L`, the route becomes `/dashboard/vc/L`. [2](#0-1) 

**Step 3 — VCDetail fetches real blockchain VC (VCDetail.tsx:15-16)**

`vcId` is extracted from the URL param (= `L`). `useGetVCQuery({ vcId: L })` returns the real on-chain VC as `data`. [3](#0-2) 

**Step 4 — `isLocal` is incorrectly resolved to `false` (VCDetail.tsx:25-28)**

`localData` is found by `vc.sha256 === vcId`. But `vcId` is `L` (the launcherId), while the sha256 stored in localStorage is the hash of the JSON file content — never equal to `L`. So `localData = null`, and `isLocal = !!localData = false`. [4](#0-3) 

**Step 5 — "Revoke" menu item appears (VCCard.tsx:305-314)**

Because `isLocal=false`, the `!isLocal` branch renders the "Revoke Verifiable Credential" menu item instead of the "Remove" item. [5](#0-4) 

**Step 6 — `revokeVC` RPC called with real `parentCoinInfo` (VCCard.tsx:252-257)**

`vcRecord` is `data` (the real blockchain VC). `vcRecord.vc?.coin.parentCoinInfo` is the real on-chain parent coin info. The RPC fires an on-chain revocation. [6](#0-5) 

---

**Root cause:** `VCDetail` determines `isLocal` by matching `vc.sha256 === vcId`, but when navigating from a local VC card that has a `vc.launcherId`, the URL param is the launcherId — never equal to the sha256 of the file. The `isLocal` flag is therefore always `false` in this path, causing the detail view to present the real blockchain VC with the on-chain Revoke action.

---

### Title
Crafted local VC file import causes `isLocal=false` in VCDetail, exposing on-chain Revoke action for the user's real VC — (`packages/gui/src/components/vcs/VCDetail.tsx`)

### Summary
Importing a crafted JSON file whose `vc.launcherId` matches a real on-chain VC causes `VCDetail` to incorrectly compute `isLocal=false`. The detail view then renders the real blockchain VC with the "Revoke Verifiable Credential" on-chain action instead of the local "Remove" action. A user who clicks through the resulting card and confirms the dialog triggers `revokeVC` with the real `parentCoinInfo`, permanently revoking their on-chain VC.

### Finding Description
`getVCFromLocalFile` stores the imported JSON verbatim in localStorage with `isLocal: true`. When the user clicks the resulting card, `VCCard` navigates to `/dashboard/vc/<vc.launcherId>`. `VCDetail` then calls `useGetVCQuery({ vcId: launcherId })`, which returns the real blockchain VC as `data`. The `localData` lookup (`vc.sha256 === vcId`) always fails because `vcId` is the launcherId, not the sha256 of the file. Consequently `isLocal = !!localData = false`, and `VCCard` is rendered with `vcRecord = data` (real VC) and `isLocal = false`, surfacing the on-chain Revoke menu item. Confirming the dialog calls `revokeVC({ vcParentId: vcRecord.vc?.coin.parentCoinInfo, fee: ... })` with the real coin's parent info.

### Impact Explanation
The user's real on-chain VC is permanently revoked. VC revocation is irreversible on-chain. This is a concrete asset/identity loss: the credential cannot be recovered after the spend.

### Likelihood Explanation
The attacker needs to know the target's `vc.launcherId` (public blockchain data, discoverable via block explorers) and deliver a crafted `.json` file to the user. The "Add Verifiable Credential from file" feature is a first-class UI action. The user must import the file, click the card, click "Revoke", and confirm with a fee — multiple steps, but the UI presents no warning that the action is on-chain rather than local, and the dialog title ("Revoke Verifiable Credential") is identical to what a legitimate revoke would show.

### Recommendation
In `VCDetail.tsx`, determine `isLocal` by also checking whether the `vcId` URL param matches any local VC's `vc.launcherId` (not only its `sha256`). If a local VC with a matching `launcherId` exists, set `isLocal=true` and render the "Remove" path. Additionally, `getVCFromLocalFile` should warn or refuse to import a file whose `vc.launcherId` matches an existing on-chain VC in `blockchainVCs`.

### Proof of Concept
1. Note the user's real VC launcherId `L` and `parentCoinInfo P` (from the existing VC card or block explorer).
2. Craft `crafted.json`: `{ "vc": { "launcherId": "L", "coin": { "parentCoinInfo": "P" } } }`.
3. In the GUI, open the VC list → More → "Add Verifiable Credential from file" → select `crafted.json`.
4. A new local VC card appears with launcherId `L`.
5. Click the card → navigates to `/dashboard/vc/L`.
6. `VCDetail` fetches the real blockchain VC; `isLocal=false`; "Revoke Verifiable Credential" menu item is visible.
7. Click "Revoke" → confirm with any fee → `revokeVC({ vcParentId: P, fee: ... })` is dispatched.
8. The real on-chain VC is revoked.

### Citations

**File:** packages/gui/src/components/vcs/VCList.tsx (L187-204)
```typescript
      const json = JSON.parse(new TextDecoder().decode(result.content));

      const sha256VC = await sha256(JSON.stringify(json));
      const sha256VCString = arrToHex(sha256VC);
      const localVCs = { ...VCsLocalStorage };
      if (fingerprint) {
        if (!localVCs[fingerprint]) {
          localVCs[fingerprint] = [];
        }
        if (localVCs[fingerprint].find((vc: any) => vc.sha256 === sha256VCString)) {
          await openDialog(
            <AlertDialog title="Error">
              <Trans>Verifiable Credential already exists.</Trans>
            </AlertDialog>,
          );
        } else {
          localVCs[fingerprint].push({ ...json, sha256: sha256VCString });
          setVCsLocalStorage(localVCs);
```

**File:** packages/gui/src/components/vcs/VCCard.tsx (L252-257)
```typescript
    } else if (confirmedWithFee >= 0) {
      /* revoke onchain */
      revokedResponse = await revokeVC({
        vcParentId: vcRecord.vc?.coin.parentCoinInfo,
        fee: parseFloat(confirmedWithFee) * 1_000_000_000_000,
      });
```

**File:** packages/gui/src/components/vcs/VCCard.tsx (L305-314)
```typescript
          {!isLocal && (
            <MenuItem onClick={() => openRevokeVCDialog('revoke')} close>
              <ListItemIcon>
                <BurnIcon color="info" />
              </ListItemIcon>
              <Typography variant="inherit" noWrap>
                {isLocal ? <Trans>Delete Verifiable Credential</Trans> : <Trans>Revoke Verifiable Credential</Trans>}
              </Typography>
            </MenuItem>
          )}
```

**File:** packages/gui/src/components/vcs/VCCard.tsx (L364-369)
```typescript
      onClick={() => {
        /* getVC doesn't get us coinId, so we must pass it in from vcList method */
        navigate(`/dashboard/vc/${vcRecord?.vc?.launcherId || vcRecord.sha256}`, {
          state: { coinId: vcRecord?.coinId },
        });
      }}
```

**File:** packages/gui/src/components/vcs/VCDetail.tsx (L15-16)
```typescript
  const { vcId } = useParams();
  const { isLoading, data } = useGetVCQuery({ vcId: vcId as string });
```

**File:** packages/gui/src/components/vcs/VCDetail.tsx (L25-44)
```typescript
  const localData =
    fingerprint && VCsLocalStorage[fingerprint]
      ? VCsLocalStorage[fingerprint].find((vc: any) => vc.sha256 === vcId)
      : null;

  function renderBackButton() {
    return (
      <IconButton onClick={() => navigate('/dashboard/vc')} sx={{ backgroundColor: 'action.hover' }}>
        <ArrowBackIosNew />
      </IconButton>
    );
  }

  function renderVCCard() {
    let proofs = proofsData?.proofs && Object.keys(proofsData?.proofs).length > 0 ? proofsData?.proofs : {};
    if (Object.keys(proofs).length === 0 && localData && localData.proof?.values) {
      proofs = localData.proof?.values;
    }
    if (isLoading || (!data && !localData)) return null;
    return <VCCard isDetail vcRecord={data || localData} proofs={proofs} isLocal={!!localData} coinId={coinId} />;
```
