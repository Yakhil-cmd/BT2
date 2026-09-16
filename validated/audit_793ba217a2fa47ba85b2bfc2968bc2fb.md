### Title
Signature replay of `is_valid_signed_package` messages across unrelated AA instances due to missing destination binding - (File: formula/evaluation.js)

### Summary
The oscript primitive `is_valid_signed_package(signed_package, address)` (and the underlying `signed_message.validateSignedMessage`) only proves that `signed_package.signed_message` was signed by `address`. It does not bind the signature to the specific AA (`this_address`) that performs the check. Any AA author who verifies a peer-signed message with this primitive but forgets to embed the verifying AA's own address (or another unique destination identifier) inside `signed_message` exposes their contract to signature replay: a signature produced for one AA instance/context can be resubmitted as valid trigger data to a different AA instance that also accepts signatures from the same signer, exactly mirroring the reported `QuestFactory.mintReceipt` bug where the signed payload lacked a domain-separator (destination/verifier address).

### Finding Description
`is_valid_signed_package` is implemented in `formula/evaluation.js` (case `'is_valid_signed_package'`, `formula/evaluation.js:1653-1702`). It evaluates the `address` argument, then calls: [1](#0-0) 

which delegates to `signed_message.validateSignedMessage(conn, signedPackage, evaluated_address, mci, ...)` in `signed_message.js:117-303`. That function verifies that `objSignedMessage.authors` contains a valid signature over `objectHash.getSignedPackageHashToSign(objSignedMessage)`: [2](#0-1) 

Crucially, `evaluated_address` — the AA-supplied "who should have signed this" address — is never mixed into the hash that gets signed; it is only compared afterward against `the_author`/`author.address` inside `validateSignedMessage`: [3](#0-2) 

`signed_package.signed_message` is an arbitrary application-defined JSON object chosen entirely by the AA author's oscript. Nothing in the primitive forces it to contain the verifying AA's own address, a chain/network id, a nonce, or a deadline. Consequently, whether a given signed package is "for" a particular AA is a convention that each AA author must implement manually.

The bundled `payment_channels.oscript` sample demonstrates the correct, but purely conventional, mitigation: it manually embeds `channel` (set to the AA's own `this_address`) and `period` in the signed message and checks them before calling `is_valid_signed_package`: [4](#0-3) 

In contrast, the bundled `order_book_exchange.oscript` sample — demonstrating the same language primitive for a different use case — verifies signed orders with `is_valid_signed_package(trigger.data.order1, $order1.address)` but never binds the order to `this_address` or to any exchange-specific identifier: [5](#0-4) 

This is the oscript analog of the `QuestFactory.mintReceipt` bug: the signed message there also omitted the verifying contract's address/chainId, allowing the same signature to be replayed across different `QuestFactory` deployments. Here, `is_valid_signed_package`'s hash-to-sign similarly omits the verifying AA's identity, so the exact same off-chain signed message (same signer, same JSON content) is valid input to `is_valid_signed_package` on any AA that checks the same signer address — including a different deployed copy of the same AA template, or an unrelated AA that happens to accept overlapping field names.

### Impact Explanation
If a user signs an off-chain message intended to authorize an action in one AA (e.g., a sell order or a channel-close balance claim) and reuses the same signing address (or key) with another AA instance built from the same or a similar oscript template (which is common, since users deploy many instances of published AA templates), an attacker (any AA trigger sender) can resubmit the previously observed signed package as `trigger.data` to the second AA. If the second AA's validation logic does not itself add a destination check, the replayed signature will be accepted as genuine authorization, potentially causing:
- Unauthorized execution of a trade/order or a channel-closing balance claim in an AA the user never intended to interact with.
- Freezing or loss of AA-held funds if the replayed authorization drives balance-changing state transitions (e.g., in the order-book or payment-channel pattern) in the "wrong" AA instance.

This matches the categories of concrete impact required (AA fund loss/freezing due to unauthorized signed-message replay).

### Likelihood Explanation
Likelihood is Medium: exploitation requires (a) an AA author who verifies peer signatures via `is_valid_signed_package` without independently embedding `this_address`/a unique instance identifier in the signed content (the order-book sample template ships exactly this way), and (b) a signer whose key/address is reused across multiple AA instances that share compatible signed-message schemas (very plausible for widely copied/forked AA templates, since Obyte addresses are commonly reused by the same user across many contracts). No malicious node, hub, or network condition is required — a normal AA trigger sender can trigger the replay directly by resubmitting previously observed data. This mirrors the C4 judge's "Medium" determination for the analogous RabbitHole issue, where the replay required overlapping `(questId, signer)` pairs across contexts rather than being trivially and universally exploitable.

### Recommendation
- Document prominently in the oscript/AA authoring guidance that `is_valid_signed_package` provides no implicit domain separation, and that AA authors MUST embed a unique destination identifier (e.g., `this_address`, a contract/version tag, and ideally an expiry timestamp or nonce) inside `signed_message` and explicitly check it before calling `is_valid_signed_package`, exactly as done in `payment_channels.oscript`.
- Consider hardening the primitive itself: optionally allow/require the AA to pass an expected "purpose"/domain string that gets checked against a mandatory field in `signed_message`, or provide a variant of `is_valid_signed_package` that automatically mixes `this_address` (and optionally `mci`/expiry) into the verification, so that safe-by-default behavior does not depend solely on author discipline.
- Audit and fix the bundled `order_book_exchange.oscript` sample (and any documentation referencing it) to add the same `this_address`/instance-binding check used in `payment_channels.oscript`, since it currently ships as an unsafe example of this primitive's usage.

### Proof of Concept
1. Deploy two AAs, `AA1` and `AA2`, both derived from the `order_book_exchange.oscript` template (identical or near-identical oscript), each maintaining independent internal balances.
2. User `U` signs an order (`signed_message = {address: U, sell_asset: X, buy_asset: Y, sell_amount: N, price: P}`) intending it to be matched only within `AA1`, using `signed_message.signMessage`/an equivalent client flow that produces a package verifiable through `is_valid_signed_package`.
3. Deposit balances for `U` in both `AA1` and `AA2` for asset `X`.
4. Anyone (attacker) submits `U`'s signed order (originally produced for `AA1`) as `trigger.data.order1` in a matching trigger sent to `AA2`, paired with a compatible counter-order for `AA2`.
5. Because `is_valid_signed_package(trigger.data.order1, $order1.address)` in `AA2`'s oscript only checks that `U` signed the content — with no check that the order was meant for `AA2` specifically — `AA2` accepts and executes the trade against `U`'s balance in `AA2`, even though `U` never intended to trade on `AA2`.
6. This is directly analogous to replaying the `QuestFactory.mintReceipt` signature (signed for one `QuestFactory` instance) against a second `QuestFactory` deployment, as described in the source report.

### Citations

**File:** formula/evaluation.js (L1693-1699)
```javascript
						signed_message.validateSignedMessage(conn, signedPackage, evaluated_address, mci, function (err, last_ball_mci) {
							if (err)
								return cb(false);
							if (last_ball_mci === null || last_ball_mci > mci)
								return cb(false);
							cb(true);
						});
```

**File:** signed_message.js (L171-186)
```javascript
		if (author.address === address)
			the_author = author;
		if (!ValidationUtils.isNonemptyObject(author.authentifiers))
			return handleResult("no authentifiers");
		for (let path in author.authentifiers) {
			if (!ValidationUtils.isNonemptyString(author.authentifiers[path]))
				return handleResult("authentifiers must be nonempty strings");
			if (author.authentifiers[path].length > constants.MAX_AUTHENTIFIER_LENGTH)
				return handleResult("authentifier too long");
		}
	}
	if (!the_author) {
		if (address)
			return handleResult("not signed by the expected address");
		the_author = authors[0];
	}
```

**File:** signed_message.js (L260-277)
```javascript
			validateOrReadDefinition(objAuthor, function (arrAddressDefinition, _last_ball_mci, last_ball_timestamp) {
				last_ball_mci = _last_ball_mci;
				var objUnit = _.clone(objSignedMessage);
				objUnit.messages = []; // some ops need it
				try {
					var objValidationState = {
						unit_hash_to_sign: objectHash.getSignedPackageHashToSign(objSignedMessage),
						last_ball_mci: last_ball_mci,
						last_ball_timestamp: last_ball_timestamp,
						bNoReferences: !bNetworkAware,
						complexity,
						max_complexity,
					};
				}
				catch (e) {
					return cb("failed to calc unit_hash_to_sign: " + e);
				}
				try {
```

**File:** test/samples/payment_channels.oscript (L40-46)
```text
							if (trigger.data.sentByPeer){
								if (trigger.data.sentByPeer.signed_message.channel != this_address)
									bounce('signed for another channel');
								if (trigger.data.sentByPeer.signed_message.period != var['period'])
									bounce('signed for a different period of this channel');
								if (!is_valid_signed_package(trigger.data.sentByPeer, $bFromB ? $addressA : $addressB))
									bounce('invalid signature by peer');
```

**File:** test/samples/order_book_exchange.oscript (L27-49)
```text
			{ // execute orders, order1 must be smaller or the same as order2; order2 is partially filled
				if: `{
					$order1 = trigger.data.order1.signed_message;
					$order2 = trigger.data.order2.signed_message;
					if (!$order1.sell_asset OR !$order2.sell_asset)
						return false;
					if ($order1.sell_asset != $order2.buy_asset OR $order1.buy_asset != $order2.sell_asset)
						return false;

					// to do check expiry

					$sell_key1 = 'balance_' || $order1.address || '_' || $order1.sell_asset;
					$sell_key2 = 'balance_' || $order2.address || '_' || $order2.sell_asset;

					$id1 = sha256($order1.address || $order1.sell_asset || $order1.buy_asset || $order1.sell_amount || $order1.price || trigger.data.order1.last_ball_unit);
					$id2 = sha256($order2.address || $order2.sell_asset || $order2.buy_asset || $order2.sell_amount || $order2.price || trigger.data.order2.last_ball_unit);

					if (var['executed_' || $id1] OR var['executed_' || $id2])
						return false;

					if (!is_valid_signed_package(trigger.data.order1, $order1.address)
						OR !is_valid_signed_package(trigger.data.order2, $order2.address))
						return false;
```
