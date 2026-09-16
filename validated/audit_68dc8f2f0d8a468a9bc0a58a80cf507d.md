### Title
Unhandled null-pointer TypeError crashes node on malformed private-payment element with missing `payload` field - ([File: network.js])

### Summary
`network.handleOnlinePrivatePayment()` dereferences `arrPrivateElements[0].payload.denomination` before verifying that `arrPrivateElements[0].payload` exists, mirroring the TightVNC `HandleZlibBPP` class of bug (dereferencing an unchecked pointer/field derived from attacker-supplied network data, causing a crash / DoS) described in CVE-2019-15680.

### Finding Description
`handleOnlinePrivatePayment(ws, arrPrivateElements, bViaHub, callbacks)` is the function that processes a `private_payment` chain, whether it is delivered "online" (peer-to-peer, `network.js`) or forwarded through the hub via a wallet device message (`wallet.js` `handlePrivatePaymentChains`, subject `'private_payments'`). Before any structural validation is done, the code executes: [1](#0-0) 
```
var unit = arrPrivateElements[0].unit;
var message_index = arrPrivateElements[0].message_index;
var output_index = arrPrivateElements[0].payload.denomination ? arrPrivateElements[0].output_index : -1;
if (!ValidationUtils.isValidBase64(unit, constants.HASH_LENGTH))
	return callbacks.ifError("invalid unit");
```
Only `ValidationUtils.isNonemptyArray(arrPrivateElements)` is checked beforehand — there is no check that `arrPrivateElements[0].payload` is a non-empty object before reading `.denomination` off it. If an attacker (an unprivileged private-payment counterparty, or a peer sending an "online" `private_payment` justsaying/direct message) sends an element whose head item omits the `payload` key (e.g. `payload: null` or field absent), `arrPrivateElements[0].payload.denomination` throws `TypeError: Cannot read properties of null/undefined (reading 'denomination')`.

This is invoked both directly from the p2p network layer for online private payments, and from `wallet.js`'s `handlePrivatePaymentChains()`, which is reached from a device/hub message with subject `'private_payments'` (`wallet.js:420-424`) — a path reachable by any paired-device correspondent or, when `body.forwarded` is used, any private-payment counterparty. While `wallet.js`'s outer validator does check `isNonemptyObject(e.payload)` for the higher-level `handlePrivatePaymentChains` path, `handleOnlinePrivatePayment` is also called for the raw "online" p2p delivery path in `network.js` where no equivalent upstream schema check exists before the field is dereferenced, and it is exported/reachable as a generic entry for private payment ingestion from an untrusted peer.

Unlike most other malformed-input handlers in this codebase (see the careful `!issuePrivateElement.payload || !issuePrivateElement.payload.inputs...` guards in `indivisible_asset.js:190-191, 201`), this particular access path lacks the analogous guard, so a single crafted message throws an uncaught synchronous exception in the middle of processing.

### Impact Explanation
An uncaught `TypeError` thrown synchronously inside a message-handling callback in Node.js crashes the process unless the caller specifically wraps the call in try/catch. This matches the CVE class exactly: null/undefined dereference on attacker-controlled, network-delivered structured data leading to Denial of Service on the receiving node/wallet. Because private payments are routinely exchanged between wallets (including via hubs and direct peer connections), a malicious counterparty in any private-asset transaction can send a truncated/malformed private element to crash the victim's wallet or full node process, disrupting the node's ability to process further units/messages until restarted.

### Likelihood Explanation
Likelihood is high for any party engaging in a private-asset payment exchange: the sender only needs to omit or null out the `payload` field of the head element of the chain before transmission — no cryptographic material, signatures, or special privileges are required, since this check occurs before any hash/signature validation of the payload.

### Recommendation
Add a guard mirroring the pattern already used elsewhere in the codebase (e.g., `indivisible_asset.js`'s `parsePrivatePaymentChain`) at the very top of `handleOnlinePrivatePayment`:
```js
if (!ValidationUtils.isNonemptyArray(arrPrivateElements))
	return callbacks.ifError("private_payment content must be non-empty array");
if (!ValidationUtils.isNonemptyObject(arrPrivateElements[0].payload))
	return callbacks.ifError("no/invalid payload in head private element");
```
before referencing `arrPrivateElements[0].payload.denomination`, and audit all other direct field accesses on `arrPrivateElements[0]` (and nested elements) in this function and its call sites for the same unchecked-access pattern. More generally, wrap top-level network/device message dispatch handlers in try/catch (or ensure the mutex/callback wrapper catches synchronous throws) so a single malformed message cannot crash the whole process, consistent with the defensive `try { doHandle(); } catch (e) { ... }` pattern already used in `wallet.js:75-80` for hub messages.

### Proof of Concept
1. Establish (or simulate) a private-asset payment relationship with a victim wallet/node (attacker is a legitimate private-payment counterparty).
2. Craft an `arrPrivateElements` array whose head element (`arrPrivateElements[0]`) has a valid `unit`/`message_index` but with `payload` set to `null` (or omitted entirely), e.g.:
```json
[{ "unit": "SOME_VALID_LOOKING_UNIT", "message_index": 0 }]
```
3. Deliver this as an "online" `private_payment` message directly to the victim node/peer (or via the hub `'private_payments'` device-message subject, depending on which call path is reachable without the higher-level object-shape pre-check).
4. `handleOnlinePrivatePayment` executes `arrPrivateElements[0].payload.denomination`, throwing an uncaught `TypeError`, crashing the Node.js process handling the connection. [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** network.js (L2375-2389)
```javascript
// handles one private payload and its chain
function handleOnlinePrivatePayment(ws, arrPrivateElements, bViaHub, callbacks){
	if (!ValidationUtils.isNonemptyArray(arrPrivateElements))
		return callbacks.ifError("private_payment content must be non-empty array");
	
	var unit = arrPrivateElements[0].unit;
	var message_index = arrPrivateElements[0].message_index;
	var output_index = arrPrivateElements[0].payload.denomination ? arrPrivateElements[0].output_index : -1;
	if (!ValidationUtils.isValidBase64(unit, constants.HASH_LENGTH))
		return callbacks.ifError("invalid unit");
	if (!ValidationUtils.isNonnegativeInteger(message_index))
		return callbacks.ifError("invalid message_index");
	if (!(ValidationUtils.isNonnegativeInteger(output_index) || output_index === -1))
		return callbacks.ifError("invalid output_index");

```

**File:** indivisible_asset.js (L187-197)
```javascript
function parsePrivatePaymentChain(conn, arrPrivateElements, callbacks){
	var bAllStable = true;
	var issuePrivateElement = arrPrivateElements[arrPrivateElements.length-1];
	if (!issuePrivateElement.payload || !issuePrivateElement.payload.inputs || !issuePrivateElement.payload.inputs[0])
		return callbacks.ifError("invalid issue private element");
	var asset = issuePrivateElement.payload.asset;
	if (!asset)
		return callbacks.ifError("no asset in issue private element");
	var denomination = issuePrivateElement.payload.denomination;
	if (!denomination)
		return callbacks.ifError("no denomination in issue private element");
```

**File:** wallet.js (L420-424)
```javascript
			case 'private_payments':
				if (conf.bIgnorePrivatePayments)
					return callbacks.ifError("private payments are ignored");
				handlePrivatePaymentChains(ws, body, from_address, callbacks);
				break;
```
