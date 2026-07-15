### Title
WalletConnect Pair Bypass List Persists After Key Deletion, Enabling Unauthorized Command Execution on Key Re-Import - (File: packages/core/src/screens/SelectKey/WalletDeleteDialog.tsx)

### Summary
When a user deletes a wallet key, the WalletConnect pair records (including their "always allow" bypass lists) stored in `dapp-pairs.yaml` are never cleaned up. If the user re-imports the same mnemonic (producing the same fingerprint), all previously-granted bypass permissions are immediately active again. A dapp that had been granted bypass for spending commands (`chia_sendTransaction`, `chia_takeOffer`, etc.) can execute those commands without any user confirmation dialog, bypassing the WalletConnect approval gate entirely.

### Finding Description

**Two separate state stores track WalletConnect authorization, but only one is cleared on key deletion.**

**Store 1 — keyring + `fingerprintSettings` (cleared on delete):**
In `WalletDeleteDialog.handleSubmit`, `deleteKey({ fingerprint })` removes the key from the daemon keyring, and `removeFingerprintPrefs()` deletes the entry from the `fingerprintSettings` localStorage object and from `sortedWallets`. [1](#0-0) 

**Store 2 — `dapp-pairs.yaml` pair records with bypass lists (never cleared on delete):**
WalletConnect pairs, including their per-command `bypass` arrays, are persisted to disk in `pairStore`. `removePair` is never called during key deletion. [2](#0-1) 

The bypass list controls whether a command executes without user confirmation: [3](#0-2) 

**Re-import restores the inconsistency:**
When the user re-imports the same mnemonic, the daemon assigns the same fingerprint (BLS public key fingerprint is deterministic). The `dispatchPairRequest` authorization check only requires `loggedInFingerprint === pair.fingerprint`: [4](#0-3) 

Because the pair record was never removed, this check passes immediately. The stale bypass list is now active for the re-imported key, and the dapp can execute any bypassed command — including `chia_sendTransaction` and `chia_takeOffer` — without showing a confirmation dialog.

**`cleanupPairingsAndSessions` does not help:**
On WalletConnect client initialization, `cleanupPairingsAndSessions` disconnects sessions whose pairing topic is absent from the pairs list. Because the pair was never removed from `dapp-pairs.yaml`, the session is not disconnected. [5](#0-4) 

### Impact Explanation

A dapp that previously held bypass permissions for spending commands (`chia_sendTransaction`, `chia_takeOffer`, `chia_cancelOffer`) retains those permissions silently after the user re-imports the same key. The user receives no confirmation dialog and no indication that the bypass is active. The dapp can initiate XCH/CAT transfers, accept or cancel offers, and perform other wallet actions without any user approval — constituting unauthorized spend, transfer, and offer acceptance/cancellation.

### Likelihood Explanation

The scenario requires the user to (1) delete a key that had an active WalletConnect pair with bypass permissions, and (2) re-import the same mnemonic. This is a realistic operational pattern: users re-import keys after device migration, accidental deletion, or wallet reset. The dapp needs only to maintain its WalletConnect session (or re-establish one from the persisted pairing) and wait for the user to log back in.

### Recommendation

In `WalletDeleteDialog.handleSubmit` (and in `deleteAllKeys`), enumerate all WalletConnect pairs whose `fingerprint` matches the deleted key and call `disconnectPair` / `removePair` for each before completing the deletion. Alternatively, filter `getPairs()` by fingerprint and revoke them as part of the key-deletion flow, mirroring how `removeFingerprintPrefs` already cleans up the localStorage side. [6](#0-5) [7](#0-6) 

### Proof of Concept

1. Connect a dapp via WalletConnect and, in the pairing dialog, enable "always allow" bypass for `chia_sendTransaction`.
2. Confirm the pair is stored: `dapp-pairs.yaml` contains the pair with `bypass: [chia_sendTransaction]`.
3. Delete the wallet key via the GUI ("Delete" from the key selection screen, confirm with fingerprint).
4. Observe that `dapp-pairs.yaml` still contains the pair record with the bypass list intact.
5. Re-import the same mnemonic phrase. The daemon assigns the same fingerprint.
6. Log in with the re-imported key.
7. From the dapp, send a `chia_sendTransaction` session request. The request is processed immediately — `dispatchPairRequest` finds the pair, the fingerprint matches, the command is in the bypass list, and `process(context)` is called without invoking `confirm()`.
8. The transaction is submitted to the wallet without any user confirmation dialog.

### Citations

**File:** packages/core/src/screens/SelectKey/WalletDeleteDialog.tsx (L89-103)
```typescript
  function removeFingerprintPrefs() {
    delete fingerprintPrefs[fingerprint];
    setFingerprintPrefs(fingerprintPrefs);
    const newSortedWalletsPrefs = sortedWalletsPrefs.filter((f: string) => f !== String(fingerprint));
    setSortedWalletsPrefs(newSortedWalletsPrefs);
  }

  async function handleSubmit(values: FormData) {
    if (values.fingerprint !== fingerprint.toString()) {
      throw new Error(t`Fingerprint does not match`);
    }
    await deleteKey({ fingerprint }).unwrap();
    removeFingerprintPrefs();
    onClose?.();
  }
```

**File:** packages/gui/src/electron/utils/pairStore.ts (L58-72)
```typescript
export function addPair(pair: Omit<PairRecord, 'updatedAt' | 'createdAt'>): PairRecord {
  if (findPair(pair.topic)) {
    throw new Error(`Pair already exists: ${pair.topic}`);
  }

  const newPair = {
    createdAt: Date.now(),
    updatedAt: Date.now(),
    ...pair,
  };

  persist([...load(), newPair]);

  return newPair;
}
```

**File:** packages/gui/src/electron/utils/pairStore.ts (L112-114)
```typescript
export function removePair(topic: string) {
  persist(load().filter((p) => p.topic !== topic));
}
```

**File:** packages/gui/src/electron/utils/dispatchPairRequest.ts (L41-44)
```typescript
  const requestedFingerprint = fingerprint ?? loggedInFingerprint;
  if (typeof requestedFingerprint !== 'number' || !requestedFingerprint || requestedFingerprint !== pair.fingerprint) {
    throw new WcError(`Fingerprint not allowed for this command`, WcErrorCode.UNAUTHORIZED_METHOD);
  }
```

**File:** packages/gui/src/electron/utils/dispatchPairRequest.ts (L56-59)
```typescript
  // if command is bypassed return true
  if (pair.bypass.includes(command)) {
    return process(context);
  }
```

**File:** packages/gui/src/components/walletConnect/WalletConnectProvider.tsx (L88-117)
```typescript
async function cleanupPairingsAndSessions(client: Client) {
  try {
    const pairs = await window.permissionsAPI.getPairs();

    // disconnect all sessions that are not in the pairs list
    const clientSessions = client.session.getAll();

    const sessionsToDisconnect = clientSessions.filter((s) => !pairs.some((p) => p.topic === s.pairingTopic));
    await Promise.all(
      sessionsToDisconnect.map((session) =>
        client.disconnect({
          topic: session.topic,
          reason: getSdkError('USER_DISCONNECTED'),
        }),
      ),
    );

    // disconnect all pairings that are not in the pairs list
    const clientPairings = client.pairing.getAll();

    const pairingsToDisconnect = clientPairings.filter(
      (clientPair) => !pairs.some((p) => clientPair.topic === p.topic),
    );

    await Promise.all(pairingsToDisconnect.map((pairing) => client.core.pairing.disconnect({ topic: pairing.topic })));
  } catch (e) {
    log('Cleanup pairings error', e);
    processError(e as Error);
  }
}
```
