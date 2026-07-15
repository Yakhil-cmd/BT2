### Title
WalletConnect `enabled` Flag Not Enforced in `processSessionRequest` — Dapps Execute Commands After WalletConnect Is Disabled - (File: `packages/gui/src/components/walletConnect/WalletConnectProvider.tsx`)

---

### Summary

The `enabled` flag that controls whether WalletConnect is active is never checked inside `processSessionRequest`. When a user disables WalletConnect, the `session_request` event listener remains registered and fully functional. Any dapp holding an existing session can continue to dispatch wallet commands — including bypassed ones that execute without any user confirmation — after the user has toggled WalletConnect off.

---

### Finding Description

`WalletConnectProvider` reads the `enabled` preference from `useWalletConnectPreferences` at line 255: [1](#0-0) 

The `useEffect` that registers the `session_request` listener has the dependency array `[client, handleDisconnectPair, processSessionRequest, updateListOfPairs]` — `enabled` is absent: [2](#0-1) 

`processSessionRequest` itself contains no guard on `enabled`. It proceeds directly to look up the pair and dispatch the command: [3](#0-2) 

The `enabled` flag is only consumed by the UI layer — to conditionally render the "Add Connection" button and the pair list — and is never wired into the actual command-processing path: [4](#0-3) 

`useWalletConnectPreferences` stores `enabled` in `localStorage` only; there is no enforcement at the IPC or main-process level: [5](#0-4) 

`dispatchPairRequest` — the main-process gate — checks pair membership, fingerprint, network, and bypass status, but has no awareness of the renderer-side `enabled` flag: [6](#0-5) 

Commands in the pair's `bypass` list execute without any confirmation dialog: [7](#0-6) 

Bypass eligibility is controlled by `allowConfirmationBypass` on each command definition. `chia_getWallets` is one confirmed example; the Commands.ts file contains 42 occurrences of this flag, and the full set of bypassable commands was not exhaustively reviewed: [8](#0-7) 

---

### Impact Explanation

When a user disables WalletConnect, they expect the feature to be fully inert — no dapp should be able to interact with their wallet. Because `processSessionRequest` never checks `enabled`, that expectation is violated:

- **Bypassed commands** execute silently and immediately, with no confirmation dialog, even though the user believes WalletConnect is off. Any command carrying `allowConfirmationBypass: true` falls into this category.
- **Non-bypassed commands** still surface a confirmation dialog, but the dialog appears even though the user has explicitly disabled WalletConnect, creating a confusing and potentially exploitable situation where a user may approve a request they believe is impossible.

This directly matches the "Bypass of WalletConnect approval... with direct security impact" criterion in the allowed High impact scope.

---

### Likelihood Explanation

The attacker only needs a previously established WalletConnect session (a normal, user-approved pairing). No leaked keys, no host compromise, and no cryptographic break are required. The WalletConnect SDK keeps sessions alive across restarts until explicitly disconnected. A dapp that was connected before the user toggled `enabled` off retains a live session and can immediately begin sending `session_request` events.

---

### Recommendation

Add an `enabled` check at the top of `processSessionRequest` in `WalletConnectProvider.tsx`. If `enabled` is `false`, respond with a `USER_REJECTED` error and return without processing:

```ts
const processSessionRequest = useCallback(async (event) => {
  const currentEnabled = enabledRef.current; // track via ref so the callback stays stable
  if (!currentEnabled) {
    await respondSessionRequestError(
      clientRef.current!, event.topic, event.id,
      'WalletConnect is disabled', WcErrorCode.USER_REJECTED,
    );
    return;
  }
  // ... existing logic
}, []);
```

Alternatively, include `enabled` in the `useEffect` dependency array and tear down / re-register the listener when `enabled` changes, disconnecting all active sessions when it transitions to `false`.

---

### Proof of Concept

1. Open Chia GUI and connect a dapp via WalletConnect (normal pairing flow).
2. Grant the dapp bypass permission for at least one command (e.g., `chia_getWallets`) via `chia_requestPermissions`.
3. Navigate to Settings → Integration and disable WalletConnect (`enabled = false`).
4. From the dapp side, send a `session_request` for the bypassed command over the still-live WalletConnect session.
5. Observe that `processSessionRequest` runs to completion — the command is dispatched to the wallet daemon and a result is returned — with no user confirmation and no enforcement of the `enabled = false` state.

### Citations

**File:** packages/gui/src/components/walletConnect/WalletConnectProvider.tsx (L255-255)
```typescript
  const { enabled } = useWalletConnectPreferences();
```

**File:** packages/gui/src/components/walletConnect/WalletConnectProvider.tsx (L297-366)
```typescript
  const processSessionRequest = useCallback(async (event: SignClientTypes.EventArguments['session_request']) => {
    const currentClient = clientRef.current;
    const currentProcess = processRef.current;

    try {
      if (!currentClient) {
        throw new Error('Client not initialized');
      }

      if (!currentProcess) {
        throw new Error('Process not initialized');
      }

      const {
        id,
        topic,
        params: {
          request: { method, params },
          chainId,
        },
      } = event;

      const pairTopic = getPairingTopicForSession(currentClient, topic);
      if (!pairTopic) {
        try {
          await respondSessionRequestError(currentClient, topic, id, 'Pairing not found', WcErrorCode.USER_REJECTED);
        } catch (e) {
          log('Failed to respond to session request without pairing:', e);
        }

        try {
          await currentClient.disconnect({ topic, reason: getSdkError('USER_DISCONNECTED') });
        } catch (e) {
          log('Failed to disconnect session without pairing:', e);
        }
        return;
      }

      const pair = await window.permissionsAPI.findPair(pairTopic);
      if (!pair) {
        try {
          await respondSessionRequestError(currentClient, topic, id, 'Pair not found', WcErrorCode.USER_REJECTED);
        } catch (e) {
          log('Failed to respond to orphan session request:', e);
        }

        try {
          await currentClient.disconnect({ topic, reason: getSdkError('USER_DISCONNECTED') });
        } catch (e) {
          log('Failed to disconnect orphan session:', e);
        }
        return;
      }

      const isMainnet = isWalletConnectChainIdMainnet(chainId);

      // parse fingerprint
      const { fingerprint, ...rest } = params;
      const commandParams = {
        ...rest,
      };

      const parsedFingerprint = parseFingerprint(fingerprint);
      if (parsedFingerprint !== undefined) {
        commandParams.fingerprint = parsedFingerprint;
      }

      log('method', method, commandParams);

      const result = await currentProcess(pairTopic, method, commandParams, { mainnet: isMainnet });
```

**File:** packages/gui/src/components/walletConnect/WalletConnectProvider.tsx (L392-425)
```typescript
  useEffect(() => {
    if (!client) {
      return undefined;
    }

    // cleanup pairings and sessions that are not in the pairs list anymore
    cleanupPairingsAndSessions(client);

    async function handleSessionRequest(event: SignClientTypes.EventArguments['session_request']) {
      try {
        await processSessionRequest(event);
      } catch (e) {
        log('Unhandled session_request error', e);
      }
    }

    async function handlePairingDelete(event: { topic: string }) {
      try {
        await handleDisconnectPair(event.topic);
      } catch (e) {
        log('Pairing delete error', e);
      }
    }

    updateListOfPairs();

    client.on('session_request', handleSessionRequest);
    client.core.pairing.events.on('pairing_delete', handlePairingDelete);

    return () => {
      client.off('session_request', handleSessionRequest);
      client.core.pairing.events.off('pairing_delete', handlePairingDelete);
    };
  }, [client, handleDisconnectPair, processSessionRequest, updateListOfPairs]);
```

**File:** packages/gui/src/components/walletConnect/WalletConnectConnections.tsx (L69-69)
```typescript
        ) : enabled && pairs.length > 0 ? (
```

**File:** packages/gui/src/hooks/useWalletConnectPreferences.ts (L12-14)
```typescript
  const [preferences, setPreferences] = useLocalStorage<WalletConnectPreferences>('walletConnectPreferences', {});

  const enabled = preferences?.enabled ?? false;
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

**File:** packages/gui/src/electron/commands/Commands.ts (L1543-1544)
```typescript
        transform: (data) => data.wallets ?? [],
        allowConfirmationBypass: true,
```
