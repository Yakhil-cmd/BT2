### Title
WalletConnect `chia_revokeVC` Approval Dialog Displays Raw `vc_parent_id` Without VC Identity Resolution — (`packages/gui/src/electron/commands/Commands.ts`)

### Summary

The WalletConnect approval dialog for `chia_wallet.vc_revoke` / `chia_revokeVC` displays only the raw `vc_parent_id` hex string under the label "Parent Coin Id". No lookup is performed to resolve this coin ID to a human-readable VC name, launcher ID, or title. A malicious dApp with an active WalletConnect session can send a crafted `chia_revokeVC` request targeting any VC the user holds, and the user cannot determine from the approval dialog which VC is being revoked.

---

### Finding Description

**Entry point — `Commands.ts` dapp schema:**

The `chia_wallet.vc_revoke` command is registered with a `dapp` array, making it reachable via WalletConnect as `chia_revokeVC`. Its param schema declares `vc_parent_id` as `type: 'string'` with no `humanize` transform and no special resolution logic: [1](#0-0) 

**Approval dialog rendering — `Confirm.tsx`:**

The `rows` array passed to the `Confirm` dialog is built from the schema's `params` list. Each row is rendered verbatim as `label` / `value` pairs with no further enrichment: [2](#0-1) 

**No special display logic for `vc_revoke` — `parseCommandDisplay.ts`:**

`parseCommandDisplay` only has enriched display logic for `chia_wallet.take_offer` and `chia_wallet.create_offer_for_ids`. `chia_wallet.vc_revoke` falls through to `return undefined`, so no VC name or launcher ID is resolved: [3](#0-2) 

**Contrast with the normal UI flow — `VCCard.tsx`:**

When the user initiates revocation from the GUI, `openRevokeVCDialog` opens `VCRevokeDialog` with the locally-resolved `vcTitle` (derived from user prefs keyed on `launcherId`), so the user sees the VC's human-readable name: [4](#0-3) [5](#0-4) 

The WalletConnect path has no equivalent resolution step.

**`chia_wallet.vc_revoke` is in `BlockedCommands.ts`** (line 29), which means it requires an explicit user confirmation — it is not auto-approved. However, the confirmation dialog itself is the problem: it shows only the raw hex `vc_parent_id`, not the VC identity. [6](#0-5) 

---

### Impact Explanation

A user who approves the WalletConnect dialog sees:

```
Confirm Revoke VC
Are you sure you want to revoke this verifiable credential?

Parent Coin Id   0xdeadbeef...cafebabe
Fee              0.001 XCH
```

There is no VC name, launcher ID, or any other identifier that lets the user verify *which* VC is being revoked. A malicious dApp can supply any `vc_parent_id` corresponding to any VC the user holds. If the user approves, `vc_revoke` is called on-chain with the attacker-chosen coin ID, irreversibly revoking the targeted VC.

This satisfies the High impact category: *"WalletConnect state that causes a user to approve... revoke... the wrong asset, identity."*

---

### Likelihood Explanation

Preconditions:
1. User has an active WalletConnect session with a malicious dApp.
2. The dApp was granted `chia_revokeVC` permission during pairing.
3. The user approves the dialog without recognizing the raw hex as belonging to an unintended VC.

Condition 3 is realistic: raw 32-byte hex strings are opaque to most users, and the dialog provides no contextual anchor (VC name, issuer, type) to help them verify intent. The revocation is irreversible on-chain.

---

### Recommendation

In `humanizeDappCommand` (or a new `parseCommandDisplay` branch for `chia_wallet.vc_revoke`), resolve `vc_parent_id` to the corresponding VC's launcher ID and user-assigned title by querying `vc_get_list` and matching on `coin.parentCoinInfo`. Display the resolved name in the approval dialog row instead of (or alongside) the raw hex. If resolution fails, surface a prominent warning that the VC identity could not be verified.

---

### Proof of Concept

1. Establish a WalletConnect session between a test dApp and the Chia GUI wallet that holds VC with launcher ID `<target_launcher_id>` whose current coin's `parentCoinInfo` is `<victim_vc_parent>`.
2. Grant the dApp `chia_revokeVC` permission during pairing.
3. From the dApp, send:
   ```json
   { "method": "chia_revokeVC", "params": { "vcParentId": "<victim_vc_parent>", "fee": 0 } }
   ```
4. Observe the approval dialog: it shows `Parent Coin Id: <victim_vc_parent>` with no VC name or launcher ID.
5. Approve the dialog.
6. Assert via `vc_get` that the targeted VC is now revoked on-chain, even though the user was never shown which VC they were revoking.

### Citations

**File:** packages/gui/src/electron/commands/Commands.ts (L1072-1091)
```typescript
  'chia_wallet.vc_revoke': {
    title: () => i18n._(/* i18n */ { id: 'Confirm Revoke VC' }),
    message: () => i18n._(/* i18n */ { id: 'Are you sure you want to revoke this verifiable credential?' }),
    confirmLabel: () => i18n._(/* i18n */ { id: 'Revoke' }),
    destructive: true,
    params: [
      {
        name: 'vc_parent_id',
        label: () => i18n._(/* i18n */ { id: 'Parent Coin Id' }),
        type: 'string',
      },
      { name: 'fee', label: () => i18n._(/* i18n */ { id: 'Fee' }), type: 'bigint', humanize: 'mojo-to-xch' },
    ],
    dapp: [
      {
        command: 'chia_revokeVC',
        title: () => i18n._(/* i18n */ { id: 'Revoke Verifiable Credential' }),
      },
    ],
  },
```

**File:** packages/gui/src/electron/dialogs/Confirm/Confirm.tsx (L383-392)
```typescript
          {rows.length > 0 && (
            <section className="rounded-xl border border-chia-border bg-chia-card overflow-hidden divide-y divide-chia-border">
              {rows.map(({ field, label, value }) => (
                <div className="px-5 py-2.5" key={field}>
                  <div className="text-xs font-semibold uppercase tracking-wider text-chia-text-muted">{label}</div>
                  <div className="mt-0.5 text-sm font-medium break-all whitespace-pre-wrap text-chia-text">{value}</div>
                </div>
              ))}
            </section>
          )}
```

**File:** packages/gui/src/electron/commands/parseCommandDisplay.ts (L438-483)
```typescript
export async function parseCommandDisplay(command: string, params: Record<string, unknown>) {
  if (command === 'chia_wallet.take_offer') {
    if (!params.offer || typeof params.offer !== 'string') {
      throw new Error('Offer is not valid');
    }

    const offerSummary = await getOfferSummary(params.offer);
    if (!offerSummary || !offerSummary.summary || !offerSummary.success) {
      throw new Error('Offer is not valid');
    }

    const { summary } = offerSummary;

    const walletDelta = offerSummaryToWalletDelta(summary);
    const walletInfos = await getWalletInfos();
    const assetKinds = offerSummaryAssetKinds(summary);
    const royaltyPercentages = offerSummaryRoyaltyPercentages(summary);
    const fees = parseMojos(summary.fees);

    return {
      walletDelta: await walletDeltaToDisplay(walletDelta, walletInfos, assetKinds, royaltyPercentages, fees),
    };
  }

  if (command === 'chia_wallet.create_offer_for_ids') {
    if (!params.offer || !isPlainObject(params.offer)) {
      throw new Error('Offer is not valid');
    }

    if (params.driver_dict !== undefined && !isPlainObject(params.driver_dict)) {
      throw new Error('Driver Dict is not valid');
    }

    const walletDelta = createOfferToWalletDelta(params.offer);
    const walletInfos = await getWalletInfos();
    const driverDict = params.driver_dict ?? {};
    const assetKinds = createOfferAssetKinds(walletDelta, walletInfos, driverDict);
    const royaltyPercentages = createOfferRoyaltyPercentages(walletDelta, driverDict);

    return {
      walletDelta: await walletDeltaToDisplay(walletDelta, walletInfos, assetKinds, royaltyPercentages, undefined),
    };
  }

  return undefined;
}
```

**File:** packages/gui/src/components/vcs/VCCard.tsx (L54-58)
```typescript
  const [vcTitlesObject, setVcTitlesObject] = usePrefs<any>('verifiable-credentials-titles', {});
  const vcTitle = React.useMemo(
    () => vcTitlesObject[vcRecord?.vc?.launcherId] || vcTitlesObject[vcRecord?.sha256] || t`Verifiable Credential`,
    [vcRecord?.vc?.launcherId, vcRecord?.sha256, vcTitlesObject],
  );
```

**File:** packages/gui/src/components/vcs/VCCard.tsx (L203-219)
```typescript
  async function openRevokeVCDialog(type: string) {
    const confirmedWithFee = await openDialog(
      <VCRevokeDialog
        vcTitle={vcTitle}
        isLocal={isLocal}
        title={
          type === 'remove' ? <Trans>Remove Verifiable Credential</Trans> : <Trans>Revoke Verifiable Credential</Trans>
        }
        content={
          type === 'remove' ? (
            <Trans>Are you sure you want to remove</Trans>
          ) : (
            <Trans>Are you sure you want to revoke</Trans>
          )
        }
      />,
    );
```

**File:** packages/gui/src/constants/BlockedCommands.ts (L28-30)
```typescript
  'chia_wallet.vc_spend',
  'chia_wallet.vc_revoke',

```
