The code path is now fully traced. Let me confirm the critical detail about how `pushTransactions` is registered and whether `withAllowUnsynced` is ever applied in the WalletConnect path.

The analysis is complete. Here is the verdict:

---

### Title
WalletConnect dApp Can Bypass `withAllowUnsynced` User Preference Gate on `chia_pushTransactions` — (`packages/gui/src/electron/api/sendCommand.ts`, `packages/api-react/src/utils/withAllowUnsynced.ts`)

### Summary

The `withAllowUnsynced` guard is designed to require **both** the user's stored preference **and** the per-call argument to be `true` before forwarding `allow_unsynced: true` to the wallet RPC. However, the WalletConnect dispatch path calls `sendCommand` directly with the raw `parsedParams`, completely bypassing this guard. A dApp that holds `chia_pushTransactions` permission can therefore supply `allow_unsynced: true` (and `sign: true`) and have those flags forwarded verbatim to `push_transactions` on the wallet RPC, regardless of whether the user has enabled the preference.

### Finding Description

**Guard design (never reached via WalletConnect):**

`withAllowUnsynced` enforces a two-key requirement: [1](#0-0) 

It is wired into the RTK mutation helper only when `mergeAllowUnsynced: true` is set: [2](#0-1) 

**`pushTransactions` RTK endpoint — no `mergeAllowUnsynced`:**

The `pushTransactions` mutation is registered without `mergeAllowUnsynced`, so even the RTK path would forward args as-is: [3](#0-2) 

**WalletConnect dispatch path — `sendCommand` called with raw `parsedParams`:**

After `parseDappParams` validates and passes through `allow_unsynced: true` (it is an explicitly allowed param in the schema), `main.tsx` calls `sendCommand` directly: [4](#0-3) 

`sendCommand` serialises `commandData` (which is `parsedParams`) verbatim into the WebSocket message with no further filtering: [5](#0-4) 

**`allow_unsynced` is an explicitly allowed dApp parameter:**

The `chia_wallet.push_transactions` command schema lists `allow_unsynced` as an optional bool, so `parseDappParams` will not strip it: [6](#0-5) 

### Impact Explanation

When the wallet is unsynced, a dApp with `chia_pushTransactions` permission can send `{sign: true, allow_unsynced: true, transactions: [...attacker_bundle...]}`. The wallet RPC receives `allow_unsynced: true` and signs the bundle against stale coin state, even though the user's preference is `false` (the default, "strict sync checks recommended" setting). The user's explicit opt-out of unsynced signing is silently overridden by the dApp. The resulting signed transaction may reference already-spent coins or incorrect balances, and the signature is valid from the wallet's perspective.

### Likelihood Explanation

Preconditions are: (1) the dApp holds `chia_pushTransactions` permission (user-granted), (2) the user clicks "Push" on the confirmation dialog, (3) the wallet is behind on sync. The dialog shows `Allow Unsynced: true` as a raw boolean field but provides no sync-status indicator and no warning that the user's preference is being overridden. A user who granted the permission and is used to approving push requests is unlikely to notice or understand the significance of the flag.

### Recommendation

Apply the same `withAllowUnsynced` gate in the WalletConnect dispatch path before calling `sendCommand`. Concretely, after `parseDappParams` returns, strip or override `allow_unsynced` to `false` unless the Redux store preference is also `true`. Alternatively, remove `allow_unsynced` from the dApp-exposed parameter list for `chia_pushTransactions` entirely and let the GUI-side preference be the sole control, consistent with the design intent documented in `withAllowUnsynced.ts`.

### Proof of Concept

1. Register a WalletConnect dApp with `chia_pushTransactions` permission.
2. Let the wallet fall behind on sync (e.g., disconnect from peers briefly, then reconnect before the GUI shows "synced").
3. Send: `chia_pushTransactions({ transactions: [crafted_bundle], sign: true, push: true, allowUnsynced: true })`.
4. Confirm the dialog.
5. Observe that the wallet RPC receives `allow_unsynced: true` and signs the bundle against stale state, despite the user's preference being `false`.
6. Contrast with the same call made through the normal GUI mutation path: `withAllowUnsynced` would force `allowUnsynced: false` and the RPC would reject with `NO_TRANSACTIONS_WHILE_SYNCING`.

### Citations

**File:** packages/api-react/src/utils/withAllowUnsynced.ts (L9-16)
```typescript
export default function withAllowUnsynced<T extends object>(state: unknown, args: T): T & { allowUnsynced?: boolean } {
  const { allowUnsynced: preferenceEnabled } = selectWalletRpcPreferences(state as RootState);
  const argsEnabled = 'allowUnsynced' in args && (args as Record<string, unknown>).allowUnsynced;

  if (preferenceEnabled && argsEnabled) {
    return { ...args, allowUnsynced: true };
  }
  return { ...args, allowUnsynced: false };
```

**File:** packages/api-react/src/utils/reduxToolkitEndpointAbstractions.ts (L111-122)
```typescript
  if (mergeAllowUnsynced) {
    return build.mutation<ReturnType<Transform>, QueryArgs<TClass, Method>>({
      ...rest,
      async queryFn(args, api, _extraOptions, baseQuery) {
        const mergedArgs = args && typeof args === 'object' ? withAllowUnsynced(api.getState(), args) : args;
        const result = await baseQuery({ service, command, args: mergedArgs });
        if (result.error) {
          return { error: result.error as any };
        }
        return { data: transformResponse(result.data as any) };
      },
    });
```

**File:** packages/api-react/src/services/wallet.ts (L571-573)
```typescript
    pushTransactions: mutation(build, WalletService, 'pushTransactions', {
      invalidatesTags: [{ type: 'Transactions', id: 'LIST' }],
    }),
```

**File:** packages/gui/src/electron/main.tsx (L293-300)
```typescript
          const response = dappCommandSchema.handler
            ? await dappCommandSchema.handler(parsedParams, {
                ...context,
                sendNotification: sendRendererNotification,
                canBypassCommand: (requestedCommand) =>
                  DappCommands.get(requestedCommand)?.allowConfirmationBypass === true,
              })
            : await sendCommand(chiaCommand, destination, parsedParams);
```

**File:** packages/gui/src/electron/api/sendCommand.ts (L190-200)
```typescript
    try {
      const messageData = JSONBigNative.stringify({
        request_id: requestId,
        command,
        destination,
        origin: 'wallet_ui',
        data: commandData,
        ack: false,
      });

      socket.send(messageData);
```

**File:** packages/gui/src/electron/commands/Commands.ts (L677-683)
```typescript
      // TODO verify param names in chia-blockchain
      {
        name: 'allow_unsynced',
        label: () => i18n._(/* i18n */ { id: 'Allow Unsynced' }),
        type: 'bool',
        isOptional: true,
      },
```
