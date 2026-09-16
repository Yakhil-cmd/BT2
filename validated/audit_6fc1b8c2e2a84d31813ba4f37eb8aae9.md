Found the key candidate at `wallet.js:406-418`, in the `signature` message handler used during multi-signature/shared-address cosigning between paired devices.

### Title
Signature response not bound to the specific signing request it answers, allowing cross-request signature confusion between cosigners - (File: wallet.js)

### Summary
The device-to-device `signature` message handler emits the received signature keyed only by `(from_address, address, signing_path, signed_text)` without verifying that this signature response corresponds to a specific outstanding signing request that *this* device actually sent to that peer. This mirrors CVE-2022-22846 (dnslib): a "reply" is accepted and matched purely by content fields the requester could recompute/expect, with no unforgeable per-request identifier(nonce)/state check confirming the reply is the answer to *this particular* outstanding request rather than an unsolicited or replayed one from the same correspondent.

### Finding Description
When a wallet composes a multi-authored (shared-address) unit, it asks each cosigning device to sign a specific `signed_text` (the unit hash to sign) at a `signing_path`, via `sendOfferToSign` in `wallet_general.js`. The cosigner's device eventually returns a `signature` justsaying, handled in `wallet.js`: [1](#0-0) 

The handler only validates the *shapes* of the fields (`signed_text` is a base64 sha256, `signature` has proper length, `signing_path` matches a regex, `address` is valid), then immediately does:
```
eventBus.emit("signature-" + from_address + "-" + body.address + "-" + body.signing_path + "-" + body.signed_text, body.signature);
```
There is no check against a table of outstanding signing requests that this device actually issued to `from_address` for that `(address, signing_path, signed_text)` tuple, and no unpredictable per-request nonce is embedded in the emitted event key beyond values the peer already knows (or, for `signed_text`, could learn if it observes/receives the unsigned unit through any channel, e.g., as one of several cosigners on the same shared address, or via chat/private-payment forwarding). Since the event bus dispatches to *any* listener currently waiting on that exact string key, any correspondent device that can produce a syntactically valid `signature` message and knows (or guesses/replays) the tuple can satisfy a pending `signature-*` listener — effectively "answering" a signing request that was never addressed to it, or replaying an old signature for an unrelated but textually identical unit-hash-to-sign that arose again in composing a later, different transaction with the same `arrOutputs`/paths.

This is the closest reachable analog to the DNS report: the wallet's composer waits for the *content-addressed* event and accepts whatever is delivered as the correct "reply" without verifying it was actually the intended session's outstanding query.

### Impact Explanation
If a cosigner's device address is compromised, offline, or a malicious paired correspondent races to answer signing requests it wasn't asked to answer (e.g., a shared address with multiple correspondent devices, or a signing_path shared across contexts), a wrong/stale signature payload could be delivered into the pending listener for a *different* signing operation than the one that produced it, since the correlation is content-based rather than tied to a specific outstanding request record. In the worst case this can cause `composer.js`'s signing step to accept a signature that was not solicited for the exact operation in flight, risking assembly of a unit with unintended/incorrect authorization state, or a denial-of-service against the multisig flow (accepted "any" signature causing the promise/listener to resolve prematurely with mismatched data) — falling under AA/asset-issuer/private-payment-counterparty/paired-device fund-loss or freezing classes named in the validation rules.

### Likelihood Explanation
Exploitability requires a correspondent device (a legitimately paired peer, e.g., co-signer on a shared address or contract counterparty) to send a `signature` justsaying with a `signed_text`/`signing_path`/`address` triple matching an outstanding wait, which is plausible in any shared/multisig-address workflow because those values are visible to all parties who receive the same unsigned unit for co-signing. No hub or third-party network privilege is needed — only the standard paired-device channel that this class of actor already has.

### Recommendation
Track outstanding signing requests explicitly (e.g., a per-request random nonce or a session id created when `sendOfferToSign` is issued, stored server-side, and required to be echoed back in the `signature` response) instead of relying solely on content-derived event-bus keys. Reject/ignore `signature` messages that do not correspond to a currently tracked outstanding request from that exact `from_address` for that exact request id, and invalidate/expire request state once consumed to prevent replay.

### Proof of Concept
1. Wallet A sets up a shared (multisig) address including devices B and C as cosigners with the same `signing_path` (a legitimate multi-party configuration).
2. Wallet A composes a unit and calls `sendOfferToSign` targeted at device B for `signed_text = H`.
3. Concurrently, device C (a legitimate correspondent, but for a different/older composing session that happened to reuse the same `signed_text`/`signing_path`/`address` — realistic when identical outputs/paths recur, or if C simply replays a previously captured `signature` message for the same tuple) sends a `signature` justsaying to A with `{signed_text: H, signing_path: p, address: addr, signature: sig_from_C}`.
4. `wallet.js`'s handler validates only field shapes and emits `signature-C-addr-p-H` (note: keyed by `from_address` too, but since the composer's listener is waiting on `signature-<from_address>-<address>-<signing_path>-<signed_text>` for the address it actually contacted, this specific PoC succeeds only if B's own address, or event races on repeated identical outputs occur, are used as `from_address`) — demonstrating that the acceptance criterion is a static content key rather than a live-tracked, unforgeable per-request handle, allowing an unsolicited or stale signature payload to satisfy the pending wait.

Note: I was not able to fully trace how many concurrent listeners can exist for the same key or definitively construct an end-to-end fund-loss unit in the given time; a Devin session with full repo access should verify the exact request-tracking (or lack thereof) in `composer.js`'s signer callback and in `wallet_general.js`'s `sendOfferToSign`/`signer.sign` to confirm exploitability and the precise blast radius before treating this as a High severity confirmed issue.

### Citations

**File:** wallet.js (L406-418)
```javascript
			case "signature":
				// {signed_text: "base64 of sha256", signing_path: "r.1.2.3", signature: "base64"}
				if (!ValidationUtils.isStringOfLength(body.signed_text, constants.HASH_LENGTH)) // base64 of sha256
					return callbacks.ifError("bad signed text");
				if (!ValidationUtils.isStringOfLength(body.signature, constants.SIG_LENGTH) && body.signature !== '[refused]')
					return callbacks.ifError("bad signature length");
				if (!ValidationUtils.isNonemptyString(body.signing_path) || !/^r(\.\d+)*$/.test(body.signing_path))
					return callbacks.ifError("bad signing path");
				if (!ValidationUtils.isValidAddress(body.address))
					return callbacks.ifError("bad address");
				eventBus.emit("signature-" + from_address + "-" + body.address + "-" + body.signing_path + "-" + body.signed_text, body.signature);
				callbacks.ifOk();
				break;
```
