### Title
Silently-ignored delivery failure in `sendPrivatePayments` can drop private-asset payloads sent to a device counterparty - ([File: wallet_general.js])

### Summary
`wallet_general.js`'s `sendPrivatePayments` forwards private-payment chains to a paired device via `device.sendMessageToDevice`, but it supplies no-op `ifOk`/`ifError` handlers, discarding any indication that the message was actually delivered/accepted before invoking `onSaved` through the queueing mechanism. This mirrors the audit finding's root cause — a critical value (transfer success/failure) is not checked before the caller proceeds as if the operation succeeded.

### Finding Description
`sendPrivatePayments` is the function used to hand off private payment chains (the actual spend proofs/blinded outputs for private assets) to the recipient device or cosigners: [1](#0-0) 

```js
function sendPrivatePayments(device_address, arrChains, bForwarded, conn, onSaved){
	var body = {chains: arrChains};
	if (bForwarded)
		body.forwarded = true;
	device.sendMessageToDevice(device_address, "private_payments", body, {
		ifOk: function(){},
		ifError: function(){},
		onSaved: onSaved
	}, conn);
}
```

Both `ifOk` and `ifError` are empty functions, meaning that regardless of whether the encrypted message is actually queued/sent successfully to the counterparty device, the calling code (`forwardPrivateChainsToDevices` and its callers in `wallet.js`/`wallet_defined_by_addresses.js`/`wallet_defined_by_keys.js`) treats the private-payment forwarding step as complete once `onSaved` fires, without any signal that the send itself failed.

This is analogous to the reported ERC20 bug: `transferFrom`'s boolean return is dropped, so the caller assumes the transfer succeeded when it may not have. Here, the "transfer" is off-chain — sending the private payment payload (proof of ownership/spend for a private asset output) to the paying counterparty — and its success/failure signal is likewise discarded.

### Impact Explanation
For private (non-public) divisible/indivisible assets, the actual value transfer is encoded in the private payload chain, not just the on-chain payment message (only a hash is public). If the underlying unit is broadcast/saved but the corresponding private payload silently fails to reach the recipient device (e.g., transient device/hub error swallowed by the empty `ifError`), the recipient never receives the proof needed to redeem/spend the private output they were paid. Because `ifOk`/`ifError` are no-ops, the sender's flow proceeds to mark the transaction/contract as completed (e.g., in `arbiter_contract.js`'s `pay`/`complete` flows and in `sendMultiPayment`'s `preCommitCb`) without any retry or error surfaced to the user, resulting in loss of the recipient's expected private funds while the sender's balance has already decreased on-chain.

### Likelihood Explanation
This path is reachable by any wallet user or paired device performing a private-asset payment (a common operation, not requiring special privileges), whenever `device.sendMessageToDevice` fails or errors for the private_payments message type; because failures are unconditionally swallowed, there is no automatic recovery or user notification, making the bug latent but silent whenever transient delivery problems occur.

### Recommendation
Wire real `ifOk`/`ifError` handling into `sendPrivatePayments`: propagate delivery errors to the caller (e.g., via the `onSaved` callback's error argument or a dedicated error callback) so failed forwarding can be retried or surfaced to the user instead of being treated as success. At minimum, log/emit a non-fatal error event so operators can detect dropped private payloads, and avoid finalizing higher-level state (contract/payment completion) until forwarding is confirmed.

### Proof of Concept
1. Alice sends a private-asset payment to Bob's device address via `sendMultiPayment`, which on `ifOk` triggers `preCommitCb` → `sendToRecipients` → `walletGeneral.sendPrivatePayments(recipient_device_address, arrChainsOfRecipientPrivateElements, false, conn, cb2)` [2](#0-1) .
2. `sendPrivatePayments` calls `device.sendMessageToDevice(...)` with empty `ifOk`/`ifError` callbacks [3](#0-2) .
3. If the underlying send to Bob's device fails (e.g., hub error, network issue), the error is discarded; `onSaved`/`cb2` still completes the precommit flow, and the on-chain unit (which already deducted Alice's private-asset balance) is committed.
4. Bob never receives the private payload needed to redeem the output, resulting in loss of the transferred private-asset funds from Bob's perspective, with no error surfaced to Alice to retry.

Note: I was unable to fully trace `device.sendMessageToDevice`'s internal semantics (e.g., whether `ifError` is guaranteed to be called synchronously on definite failure vs. only after retries) within the available indexed content, so the precise failure window is based on the visible call pattern rather than a full trace of `device.js`. A full session with complete file access would be needed to confirm the exact retry/timeout semantics.

### Citations

**File:** wallet_general.js (L18-28)
```javascript
// unlike similar function in network, this function sends multiple chains in a single package
function sendPrivatePayments(device_address, arrChains, bForwarded, conn, onSaved){
	var body = {chains: arrChains};
	if (bForwarded)
		body.forwarded = true;
	device.sendMessageToDevice(device_address, "private_payments", body, {
		ifOk: function(){},
		ifError: function(){},
		onSaved: onSaved
	}, conn);
}
```

**File:** wallet.js (L2405-2408)
```javascript
							var sendToRecipients = function(cb2){
								if (recipient_device_address) {
									walletGeneral.sendPrivatePayments(recipient_device_address, arrChainsOfRecipientPrivateElements, false, conn, cb2);
								} 
```
