### Title
WalletConnect `chia_sendTransaction` Accepts Dapp-Controlled `wallet_id` Hidden from User Confirmation Dialog — (File: `packages/gui/src/electron/commands/Commands.ts`)

---

### Summary

The `chia_sendTransaction` WalletConnect command accepts a dapp-supplied `wallet_id` parameter that selects which wallet the funds are drawn from, but this parameter is marked `hide: true` in the confirmation dialog schema. A malicious dapp can silently redirect a spend to a different wallet under the same fingerprint than the user expects, and the user's confirmation dialog will show only the amount, fee, and destination address — never the source wallet — causing the user to unknowingly authorize a spend from the wrong wallet.

---

### Finding Description

In `packages/gui/src/electron/commands/Commands.ts`, the `chia_wallet.send_transaction` command definition exposes `wallet_id` as a dapp-controllable parameter with `hide: true`:

```ts
// Commands.ts lines 131-177
'chia_wallet.send_transaction': {
  params: [
    { name: 'amount', ... },
    { name: 'fee', ... },
    { name: 'address', ... },
    { name: 'wallet_id', label: ..., type: 'number', hide: true },  // ← hidden from user
    ...
  ],
  dapp: [{
    command: 'chia_sendTransaction',
    requiresSync: true,
    defaults: { wallet_id: 1 },   // ← default, but dapp can override
  }],
},
```

The `parseDappParams` function in `packages/gui/src/electron/commands/parseDappParams.ts` validates that `wallet_id` is in the allowed param list and coerces it to a number, but places no restriction on which wallet ID the dapp may supply. The test in `parseDappParams.test.ts` explicitly confirms that `walletId: 2` is accepted and forwarded as `wallet_id: 2`.

The `dispatchPairRequest` function in `packages/gui/src/electron/utils/dispatchPairRequest.ts` enforces only that the pair exists, the command is allowed, the network matches, and the fingerprint matches the logged-in key. It performs no check that the supplied `wallet_id` belongs to the wallet the user associated with the pair.

The confirmation dialog rendered in `packages/gui/src/electron/dialogs/Confirm/Confirm.tsx` iterates over `rows`, which are built from params that do **not** have `hide: true`. Because `wallet_id` carries `hide: true`, it is never rendered in the dialog the user sees before clicking "Confirm."

---

### Impact Explanation

A user who has multiple wallets under the same fingerprint (e.g., wallet 1 = XCH with 1 XCH, wallet 5 = XCH with 100 XCH) and who has approved a dapp for `chia_sendTransaction` can be silently redirected. The dapp sends `{ walletId: 5, amount: ..., address: attacker_address }`. The confirmation dialog shows only the amount, fee, and destination. The user clicks "Confirm" believing they are spending from wallet 1, but the spend is executed against wallet 5. This constitutes an unauthorized balance/accounting change affecting XCH — the user approves a transaction from the wrong wallet without any indication of which wallet is the source.

---

### Likelihood Explanation

Any dapp that has been granted `chia_sendTransaction` permission can exploit this immediately without any additional user interaction. The user has no way to detect the substitution from the confirmation dialog. The only prerequisite is that the victim has more than one XCH-type wallet under the same fingerprint, which is a normal configuration for users who have created multiple wallets.

---

### Recommendation

Remove `hide: true` from the `wallet_id` parameter in the `chia_wallet.send_transaction` command definition, so the source wallet is always displayed in the confirmation dialog. Additionally, consider restricting the dapp-supplied `wallet_id` to only the wallet(s) explicitly associated with the approved pair at pairing time, analogous to how `fingerprint` is bound to the pair record.

---

### Proof of Concept

1. User connects a dapp via WalletConnect and approves `chia_sendTransaction`. The pair is recorded with `fingerprint: 123456`.
2. User has wallet 1 (XCH, 1 XCH) and wallet 5 (XCH, 100 XCH) under fingerprint 123456.
3. Dapp sends a WalletConnect `session_request`:
   ```json
   {
     "method": "chia_sendTransaction",
     "params": {
       "fingerprint": 123456,
       "walletId": 5,
       "amount": "100000000000000",
       "fee": "0",
       "address": "xch1attacker..."
     }
   }
   ```
4. `parseDappParams` accepts `wallet_id: 5` (it is in the allowed param list).
5. `dispatchPairRequest` passes all checks (pair found, command allowed, fingerprint matches).
6. The confirmation dialog renders: Amount, Fee, Address — `wallet_id` is absent because `hide: true`.
7. User clicks "Confirm" believing they are sending 100 XCH from wallet 5 — but they intended to send from wallet 1.
8. The spend executes against wallet 5, draining 100 XCH to the attacker's address.

**Relevant code locations:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** packages/gui/src/electron/commands/Commands.ts (L149-176)
```typescript
      {
        name: 'wallet_id',
        label: () => i18n._(/* i18n */ { id: 'Wallet Id' }),
        type: 'number',
        hide: true,
      },
      {
        name: 'memos',
        label: () => i18n._(/* i18n */ { id: 'Memos' }),
        type: 'json',
        isOptional: true,
        hide: true,
      },
      {
        name: 'puzzle_decorator',
        label: () => i18n._(/* i18n */ { id: 'Puzzle Decorator' }),
        type: 'json',
        isOptional: true,
      },
    ],
    dapp: [
      {
        command: 'chia_sendTransaction',
        title: () => i18n._(/* i18n */ { id: 'Send Transaction' }),
        requiresSync: true,
        defaults: { wallet_id: 1 },
      },
    ],
```

**File:** packages/gui/src/electron/commands/parseDappParams.ts (L33-48)
```typescript
  // validate via assert if all params are allowed for the dapp
  Object.keys(nextParams).forEach((key) => {
    if (!dappParamsMap.has(key)) {
      throw new Error(`param not allowed for dapp: ${key}`);
    }
  });

  // apply all default values if they are not provided (aliases can use them)
  // devs can apply default values that are not in params list
  if (dappCommandSchema.defaults) {
    for (const [key, value] of Object.entries(dappCommandSchema.defaults)) {
      if (nextParams[key] === undefined) {
        nextParams[key] = value;
      }
    }
  }
```

**File:** packages/gui/src/electron/utils/dispatchPairRequest.ts (L28-54)
```typescript
  // verify if the command is allowed for this pair
  if (!pair.commands.includes(command)) {
    throw new WcError(`Command not allowed for this pair.`, WcErrorCode.UNAUTHORIZED_METHOD);
  }

  const { fingerprint } = params;

  // verify if the network is the same as the pair's network
  if (isMainnetValue !== pair.mainnet) {
    throw new WcError(`Network mismatch`, WcErrorCode.UNSUPPORTED_CHAINS);
  }

  // verify if the requested fingerprint is allowed for this pair
  const requestedFingerprint = fingerprint ?? loggedInFingerprint;
  if (typeof requestedFingerprint !== 'number' || !requestedFingerprint || requestedFingerprint !== pair.fingerprint) {
    throw new WcError(`Fingerprint not allowed for this command`, WcErrorCode.UNAUTHORIZED_METHOD);
  }

  const context = {
    pair,
    fingerprint: requestedFingerprint,
  };

  // Dapps may not switch the active key for an existing pair.
  if (fingerprint !== undefined && fingerprint !== loggedInFingerprint) {
    throw new WcError(`Fingerprint not allowed for this command`, WcErrorCode.UNAUTHORIZED_METHOD);
  }
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
