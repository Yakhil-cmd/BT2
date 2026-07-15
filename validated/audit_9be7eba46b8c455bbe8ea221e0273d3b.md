The code trace is complete. Here is the full analysis:

---

### Title
`chia_sendTransaction` `wallet_id` Hidden from Confirmation Dialog Allows dApp to Target Arbitrary Wallet — (`packages/gui/src/electron/commands/Commands.ts`)

### Summary

A dApp that has been granted `chia_sendTransaction` permission can supply an arbitrary `wallet_id` in its WalletConnect request. The parameter is accepted by `parseDappParams`, passed through to the `send_transaction` RPC, but is **explicitly hidden** from the user's confirmation dialog via `hide: true`. The user approves a transaction without knowing which wallet is being targeted.

---

### Finding Description

**Step 1 — Parameter is declared and accepted.**

In `Commands.ts`, `wallet_id` is listed as a valid parameter for `chia_wallet.send_transaction`: [1](#0-0) 

The `hide: true` flag means it is accepted from the dApp but **not rendered** in the confirmation dialog. The default `{ wallet_id: 1 }` is only applied when the dApp omits the field: [2](#0-1) 

**Step 2 — `parseDappParams` accepts the dApp-supplied value.**

Defaults are applied only when `nextParams[key] === undefined`: [3](#0-2) 

A dApp sending `{ walletId: 2, amount, fee, address }` passes the allowlist check (because `wallet_id` is in `dappParamsMap`) and the default of `1` is never applied. This is explicitly confirmed by the existing test suite: [4](#0-3) 

**Step 3 — The value flows unmodified to the RPC.**

`useWalletConnectCommand.handleProcess` serializes `commandParams` (which includes the attacker-controlled `wallet_id`) and dispatches it via `window.permissionsAPI.dispatchAsPair`: [5](#0-4) 

`dispatchPairRequest` checks fingerprint, network, and command allowlist — but performs **no validation of `wallet_id`**: [6](#0-5) 

**Step 4 — The confirmation dialog hides `wallet_id`.**

The user sees amount (humanized as XCH via `mojo-to-xch`), fee, and address. The `wallet_id` field is hidden: [7](#0-6) 

The amount is always humanized as XCH regardless of the actual wallet type targeted, so if `wallet_id` points to a CAT wallet, the displayed amount is still rendered in XCH units — a misleading representation.

---

### Impact Explanation

The user is shown a confirmation dialog for "Send Transaction" with amount, fee, and address, but has no visibility into which wallet is being debited. A dApp can silently redirect the `send_transaction` RPC to any wallet_id it chooses. The confirmation dialog provides no signal that the targeted wallet differs from the expected standard wallet (id=1).

Whether the Chia daemon accepts `send_transaction` for a non-standard wallet type (CAT, CRCAT, etc.) is a backend question outside this GUI codebase. If the daemon routes `send_transaction` to any wallet that implements `generate_signed_transaction` (which CAT wallets do), funds could be moved from the wrong wallet. Even if the daemon rejects the call, the user has approved a transaction they cannot fully evaluate — a spoofing of wallet selection state that fits the **High** impact category: *"causes a user to approve … the wrong asset, identity, amount, destination, or status."*

---

### Likelihood Explanation

Any dApp that has been granted `chia_sendTransaction` permission can trigger this immediately. No additional privileges, leaked keys, or social engineering beyond the initial pairing are required. The test suite itself documents the behavior as working as designed, making it stable and reproducible.

---

### Recommendation

1. **Remove `wallet_id` from the dApp-controllable parameter list** for `chia_sendTransaction`, or lock it to `1` (standard wallet) unconditionally before dispatching.
2. If multi-wallet targeting is intentional, **remove `hide: true`** so the wallet id (and ideally wallet type/name) is shown in the confirmation dialog.
3. Add a GUI-side guard that validates `wallet_id` corresponds to a `WalletType.STANDARD_WALLET` before forwarding to the RPC.

---

### Proof of Concept

```
1. Pair a dApp with chia_sendTransaction permission.
2. Send a WalletConnect session_request:
   method: "chia_sendTransaction"
   params: { walletId: 2, amount: "1000000000000", fee: "0", address: "<victim_address>" }
3. Observe the confirmation dialog: shows amount=1 XCH, fee=0, address — no wallet_id shown.
4. User clicks "Send".
5. The RPC dispatched to the daemon is:
   send_transaction { wallet_id: 2, amount: 1000000000000, fee: 0, address: "..." }
   targeting wallet 2 (CAT/CRCAT/other), not the standard XCH wallet.
```

The test at `parseDappParams.test.ts:63–75` is a ready-made unit-level proof that `wallet_id: 2` survives `parseDappParams` unchanged. [8](#0-7)

### Citations

**File:** packages/gui/src/electron/commands/Commands.ts (L135-168)
```typescript
    params: [
      {
        name: 'amount',
        label: () => i18n._(/* i18n */ { id: 'Amount' }),
        type: 'bigint',
        humanize: 'mojo-to-xch',
      },
      {
        name: 'fee',
        label: () => i18n._(/* i18n */ { id: 'Fee' }),
        type: 'bigint',
        humanize: 'mojo-to-xch',
      },
      { name: 'address', label: () => i18n._(/* i18n */ { id: 'Address' }), type: 'string' },
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
```

**File:** packages/gui/src/electron/commands/Commands.ts (L169-176)
```typescript
    dapp: [
      {
        command: 'chia_sendTransaction',
        title: () => i18n._(/* i18n */ { id: 'Send Transaction' }),
        requiresSync: true,
        defaults: { wallet_id: 1 },
      },
    ],
```

**File:** packages/gui/src/electron/commands/parseDappParams.ts (L42-48)
```typescript
  if (dappCommandSchema.defaults) {
    for (const [key, value] of Object.entries(dappCommandSchema.defaults)) {
      if (nextParams[key] === undefined) {
        nextParams[key] = value;
      }
    }
  }
```

**File:** packages/gui/src/electron/commands/parseDappParams.test.ts (L46-76)
```typescript
    it('applies schema defaults only when the dapp omitted the value', () => {
      expect(
        parseDappParams(
          'chia_sendTransaction',
          serialize({
            amount: '1',
            fee: '0',
            address: 'txch1address',
          }),
        ),
      ).toMatchObject({
        amount: 1n,
        fee: 0n,
        address: 'txch1address',
        wallet_id: 1,
      });

      expect(
        parseDappParams(
          'chia_sendTransaction',
          serialize({
            amount: '1',
            fee: '0',
            address: 'txch1address',
            walletId: 2,
          }),
        ),
      ).toMatchObject({
        wallet_id: 2,
      });
    });
```

**File:** packages/gui/src/hooks/useWalletConnectCommand.tsx (L84-99)
```typescript
    const commandParams = {
      ...params,
    };

    // remove old waitForConfirmation - back compatibility, we are using requiresSync instead
    if ('waitForConfirmation' in commandParams) {
      delete commandParams.waitForConfirmation;
    }

    log('Executing', command, commandParams);

    const result = await window.permissionsAPI.dispatchAsPair({
      topic: pairTopic,
      command,
      params: JSONbig.stringify(commandParams),
    });
```

**File:** packages/gui/src/electron/utils/dispatchPairRequest.ts (L14-66)
```typescript
export async function dispatchPairRequest<T>(
  topic: string,
  command: string,
  params: Record<string, unknown>,
  process: (context: DispatchPairRequestContext) => Promise<T>,
  confirm: () => Promise<boolean>,
): Promise<T> {
  const [loggedInFingerprint, isMainnetValue] = await Promise.all([getLoggedInFingerprint(), isMainnet()]);

  const pair = findPair(topic);
  if (!pair) {
    throw new WcError(`Pair not found`, WcErrorCode.USER_REJECTED);
  }

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

  // if command is bypassed return true
  if (pair.bypass.includes(command)) {
    return process(context);
  }

  const isAllowed = await confirm();
  if (isAllowed === true) {
    return process(context);
  }

  throw new WcError(`Command not allowed for this pair.`, WcErrorCode.UNAUTHORIZED_METHOD);
```
