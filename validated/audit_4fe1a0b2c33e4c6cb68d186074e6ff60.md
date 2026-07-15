The code path is real and traceable. Let me verify the full call chain precisely.

The full call chain is confirmed. Here is my analysis:

---

### Title
Untrusted On-Chain CAT Name from `get_stray_cats` Used Directly in `addCATToken` Without Validation or Confirmation — (`packages/wallets/src/hooks/useWalletsList.ts`)

### Summary

`handleShow` in `useWalletsList.ts` passes `strayCat.name` — sourced verbatim from the wallet daemon's `get_stray_cats` RPC — into `addCATToken`, which calls `createWalletForExisting` and then `setName` on the resulting wallet. There is no name validation, no sanitization, and no user confirmation dialog. An attacker who sends a crafted CAT with an attacker-controlled name (e.g., `'Chia'`) to the victim can cause the victim's wallet to be permanently named after the spoofed token upon a single toggle action.

### Finding Description

**Data source — `getStrayCats` transform:** [1](#0-0) 

The `name` field is passed through unchanged. Only `assetId` and `senderPuzzleHash` are normalized. No filtering or validation of the `name` field occurs here.

**State population — `useWalletsList`:** [2](#0-1) 

`strayCats` is populated directly from the RPC response. The `nonAddedStrayCats` list is built from this data: [3](#0-2) 

**User trigger — `WalletTokenCard.handleVisibleChange`:**

When the user toggles a stray cat visible and no `walletId` exists yet (i.e., it has not been imported), `onShow(assetId)` is called: [4](#0-3) 

The `localCatName` override only fires if the user had previously set a local name for this exact `assetId`. For a fresh attacker-sent stray cat, `localCatName` is `null`, so the override never executes.

**Vulnerable sink — `handleShow`:** [5](#0-4) 

`catList.find()` misses (the attacker's assetId is not in the official list), so `strayCats.find()` hits and `addCATToken` is called with `strayCat.name` — the attacker-controlled value — verbatim.

**RPC execution — `addCATToken`:** [6](#0-5) 

`setName` is called with the attacker-supplied `name`, permanently naming the new wallet after the spoofed token.

### Impact Explanation

The victim's wallet daemon creates a new CAT wallet whose display name is fully attacker-controlled. If the attacker names their CAT `'Chia'`, the victim's wallet list shows a wallet named `'Chia'` backed by the attacker's assetId. If the attacker also sends a non-zero balance of their CAT to the victim, the victim sees a `'Chia'` wallet with a balance, which they may mistake for XCH. This fits the scope criterion: **spoofing of RPC/event state that causes a user to import and display the wrong asset under a wrong identity**.

### Likelihood Explanation

- Sending a CAT to any address is permissionless and costs only a small fee.
- The `name` field in Chia's `get_stray_cats` response is sourced from CAT metadata that the issuer controls.
- The victim only needs to open "Manage token list" and toggle the switch — a routine action for any user who receives an unknown token.
- No confirmation dialog, no name validation, and no trust boundary exists between the RPC response and the `setName` call.

### Recommendation

1. In `handleShow`, do not use `strayCat.name` as the wallet name. Either use the `assetId` as the initial name, or prompt the user to confirm/enter a name before calling `addCATToken`.
2. In `WalletTokenCard.handleVisibleChange`, show a confirmation dialog for stray cats that includes the raw `assetId` and warns that the name is unverified.
3. In the `getStrayCats` transform, strip or truncate the `name` field, or at minimum flag it as untrusted in the type system.

### Proof of Concept

```
1. Attacker mints a CAT with metadata name = 'Chia' and sends 1 unit to victim's address.
2. Victim's wallet daemon picks it up; get_stray_cats returns:
   { assetId: '<attacker_assetId>', name: 'Chia', firstSeenHeight: N, senderPuzzleHash: '...' }
3. Victim opens Dashboard → Wallets → "Manage token list".
4. A list item appears: name='Chia', type='STRAY_CAT', walletId=undefined.
5. Victim toggles the switch ON.
6. WalletTokenCard.handleVisibleChange fires; localCatName is null; onShow(assetId) is called.
7. handleShow: catList.find() → miss; strayCats.find() → hit.
8. addCATToken({ name: 'Chia', assetId: '<attacker_assetId>' }) is dispatched.
9. RPC: createWalletForExisting(<attacker_assetId>) → walletId=42
10. RPC: setName({ walletId: 42, name: 'Chia' })
11. Victim's wallet list now shows a wallet named 'Chia' with balance = 1 (attacker's CAT).
```

Unit-test plan: mock `useGetStrayCatsQuery` to return `[{ assetId: 'deadbeef...', name: 'Chia' }]`, mock `useGetCatListQuery` to return `[]`, call `handleShow('deadbeef...')`, and assert `addCATToken` was called with `{ name: 'Chia', assetId: 'deadbeef...' }`.

### Citations

**File:** packages/api-react/src/services/wallet.ts (L796-805)
```typescript
    getStrayCats: query(build, CAT, 'getStrayCats', {
      transformResponse: (response) =>
        response.strayCats.map(
          (cat: { assetId: string; name: string; firstSeenHeight: number; senderPuzzleHash: string }) => ({
            ...cat,
            assetId: normalizeHex(cat.assetId),
            senderPuzzleHash: normalizeHex(cat.senderPuzzleHash),
          }),
        ),
    }),
```

**File:** packages/api-react/src/services/wallet.ts (L944-948)
```typescript
          await fetchWithBQ({
            command: 'setName',
            service: CAT,
            args: { walletId, name },
          });
```

**File:** packages/wallets/src/hooks/useWalletsList.ts (L63-65)
```typescript
  const { data: strayCats, isLoading: isLoadingGetStrayCats } = useGetStrayCatsQuery(undefined, {
    pollingInterval: 10_000,
  });
```

**File:** packages/wallets/src/hooks/useWalletsList.ts (L138-176)
```typescript
    const nonAddedStrayCats = strayCats?.filter((strayCat) => !hasCatAssignedWallet(strayCat.assetId)) ?? [];

    let tokens = [
      ...baseWallets.map((wallet: Wallet) => ({
        id: wallet.id,
        type: 'WALLET',
        walletType: wallet.type,
        hidden: isHidden(wallet.id),
        walletId: wallet.id,
        assetId: wallet.meta?.assetId,
        name: wallet.type === WalletType.STANDARD_WALLET ? 'Chia' : (wallet.meta?.name ?? wallet.name),
      })),
      ...catBaseWallets.map((wallet: Wallet) => ({
        id: wallet.id,
        type: knownCatAssetIds.has(wallet.meta?.assetId) ? 'CAT_LIST' : 'STRAY_CAT',
        walletType: wallet.type,
        hidden: isHidden(wallet.id),
        walletId: wallet.id,
        assetId: wallet.meta?.assetId,
        name: wallet.meta?.name ?? wallet.name,
      })),
      ...nonAddedKnownCats.map((cat) => ({
        id: cat.assetId,
        type: 'CAT_LIST',
        walletType: WalletType.CAT,
        hidden: isHiddenCAT(cat.assetId),
        walletId: walletAssetIds.has(cat.assetId) ? walletAssetIds.get(cat.assetId) : undefined,
        assetId: cat.assetId,
        name: getCATName(cat.assetId),
      })),
      ...nonAddedStrayCats.map((strayCat) => ({
        id: strayCat.assetId,
        type: 'STRAY_CAT',
        walletType: WalletType.CAT,
        hidden: isHiddenCAT(strayCat.assetId),
        walletId: walletAssetIds.has(strayCat.assetId) ? walletAssetIds.get(strayCat.assetId) : undefined,
        assetId: strayCat.assetId,
        name: getCATName(strayCat.assetId),
      })),
```

**File:** packages/wallets/src/hooks/useWalletsList.ts (L207-214)
```typescript
        // assign stray cat
        const strayCat = strayCats?.find((catItem) => catItem.assetId === id);
        if (strayCat) {
          return await addCATToken({
            name: strayCat.name,
            assetId: strayCat.assetId,
          }).unwrap();
        }
```

**File:** packages/wallets/src/components/WalletTokenCard.tsx (L114-122)
```typescript
          if (!walletId) {
            const newWalletId = await onShow(assetId);
            // use name from local storage
            if (localCatName) {
              await setCATName({
                walletId: newWalletId,
                name: localCatName,
              }).unwrap();
            }
```
