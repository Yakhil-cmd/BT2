Confirmed: the "data" app message type has no uniqueness constraint in `validateInlinePayload` — unlike `data_feed` (`objValidationState.bHasDataFeed`), `profile` (`objValidationState.bHasProfile`), or `vote`/`poll`, a unit can contain multiple `app: 'data'` messages, each only checked for being a non-null object [1](#0-0) . `MAX_MESSAGES_PER_UNIT` is the only cap on message count [2](#0-1) .

### Title
Silent truncation of multiple `data` messages in `formula` authentifier definitions enables hidden-payload bypass of address/AA spending conditions - (File: definition.js)

### Summary
When a smart-contract address definition uses the `['formula', ...]` opcode, the oscript/formula evaluator builds `trigger.data` by scanning `objUnit.messages` and taking only the **first** `app: 'data'` message, explicitly discarding all subsequent ones:
```js
objUnit.messages.forEach(function (message) {
    if (message.app === 'data' && !trigger.data) // use the first data mesage, ignore the subsequent ones
        trigger.data = message.payload;
});
``` [3](#0-2) 

This is structurally identical to the librosa `to_mono` bug class: a single "authoritative" reduction (first-wins) is applied for policy/authentification decisions, while a different, more complete representation (all `data` messages, in full, actually gets persisted and delivered downstream) is what other consumers of the unit (light wallets, dApps, human-readable explorers, or other definition clauses evaluating `trigger.data` differently) will observe. There is a "hidden channel" — data placed in the second, third, etc. `app: 'data'` message — that is invisible to any `formula` condition evaluating `trigger.data`, yet the message is still valid, still gets saved to the DAG, and its payload is still delivered to whoever reads the unit's messages array directly (e.g., an AA reading `trigger.data` via a different code path, a wallet UI, or a counter-party manually inspecting the unit).

### Finding Description
Ocore places no restriction on the number of `app: 'data'` messages a unit may contain — `validateInlinePayload`'s `"data"` case only requires the payload be an object [4](#0-3) , in contrast to `data_feed`, `profile`, `vote`, and `poll`, which explicitly enforce "only one" via `objValidationState.bHasXxx` flags [5](#0-4) [6](#0-5) [7](#0-6) .

Meanwhile, the `formula` opcode used inside address definitions (multisig/smart contract spending conditions) constructs its `trigger.data` view of the unit by taking only the first `data` message and silently ignoring the rest [8](#0-7) . This produces a processing differential: the *authentication logic* that decides whether a signature/authorization is valid sees only a truncated view of the unit's `data` messages, while the *actual persisted unit* — which other parties, wallets, AAs, or explorer/monitoring tools read directly from `objUnit.messages` — contains the full, untruncated set.

An attacker who controls both message ordering and content in a self-authored (or negotiated multi-sig/contract) unit can:
1. Place an innocuous/expected `data` payload as the *first* `data` message so that any `formula`-based condition inspecting `trigger.data` (e.g., `{trigger.data.amount} == 100`) validates against benign values.
2. Append a second (or further) `data` message with different/malicious content that is never inspected by the formula-based authentifier, but which is fully delivered, stored, and interpretable by any off-chain application, oracle, or human reviewing the unit's messages — a discrepancy directly analogous to the LFE-channel/audio-downmix bypass, where the "moderated" representation (formula's `trigger.data`) diverges from the "actually delivered" representation (the full unit).

This is reachable by any unpriveleged poster of a unit spent from/authorized by such a definition — no special network position or trust is required, matching the "unit validation ... oscript/ojson evaluation" reachable-surface criteria.

### Impact Explanation
Contracts and multi-party arrangements (e.g., prosaic/arbiter contracts, escrow-style definitions, or bespoke smart-contract addresses built with `['formula', ...]`) that gate authorization/spending on `trigger.data` fields can be tricked: the on-chain authorization check sees the sanitized/expected first `data` message, while a counterparty (or the same attacker acting against another observer) can smuggle a second, differently-interpreted `data` payload in the same unit that downstream consumers (bots, oracles, other AAs manually reading `objUnit.messages`, off-chain services) act upon. This can lead to spending conditions being satisfied on manipulated/inconsistent inputs, effectively a data-hiding channel that defeats intended "review what you sign" semantics for formula-guarded definitions — a concrete authorization/funds-control integrity issue (CWE-20, improper input validation of which data is authoritative).

### Likelihood Explanation
Medium: exploitation requires a definition that uses the `formula` opcode referencing `trigger.data`, and a counterparty or process that trusts/parses the *full* unit's `data` messages rather than only the first one (e.g. a wallet, dApp backend, or another AA/formula elsewhere in the same or referencing definition). Given that ocore explicitly supports multiple `data` messages per unit (no per-app uniqueness cap, unlike `data_feed`/`profile`/`vote`) and ships sample oscripts sending multiple `app: 'data'` messages conditionally [9](#0-8) , the pattern of multiple data messages in one unit is an intended, common use case, making the divergence readily triggerable by any unit author.

### Recommendation
Either (a) enforce single-`data`-message-per-unit semantics analogous to `data_feed`/`profile` in `validateInlinePayload`, or (b) change the `formula` opcode's construction of `trigger.data` in `definition.js` to expose *all* `data` messages (e.g. as an array) rather than silently keeping only the first and discarding the rest, so that formula-based authentifiers cannot be bypassed by hiding content in subsequent `data` messages. At minimum, document/flag this behavior and audit `formula`-guarded definitions and AA responses that depend on `trigger.data` for input-shadowing risk.

### Proof of Concept
1. Define an address with `['formula', "{trigger.data.action} == \"withdraw_small\""]` as (part of) its spending condition, intended to only authorize based on the declared `action`.
2. Compose and post a unit spending from that address with two `app: 'data'` messages:
   - Message 1: `{ "action": "withdraw_small" }` (satisfies the formula, since `objUnit.messages.forEach` sets `trigger.data` from the first `data` message it encounters per `definition.js:1204-1208`).
   - Message 2: `{ "action": "withdraw_all", "amount": <large> }` (never inspected by the formula, but present in `objUnit.messages` and delivered to any counterparty/service reading the full unit).
3. The unit passes `validateInlinePayload`'s `"data"` case for both messages since no uniqueness check exists [4](#0-3) , and the `formula` authentifier authorizes the unit based only on the first message's content [3](#0-2) .
4. Any external system (wallet UI, bot, AA, or reviewer) that parses `objUnit.messages` directly (rather than replicating the "first data message wins" rule) will see and may act on the second, unvetted `data` payload — demonstrating the processing differential between the authorization path and the actual persisted/delivered content.

### Citations

**File:** validation.js (L212-215)
```javascript
		if (!isNonemptyArray(objUnit.messages))
			return callbacks.ifUnitError("missing or empty messages array");
		if (objUnit.messages.length > constants.MAX_MESSAGES_PER_UNIT && !bGenesis)
			return callbacks.ifUnitError("too many messages");
```

**File:** validation.js (L1814-1817)
```javascript
		case "vote":
			if (objValidationState.bHasVote && (objValidationState.last_ball_mci >= constants.pemCurvesFixMci || !objValidationState.hasBall && storage.getMinRetrievableMci() >= constants.pemCurvesFixMci))
				return callback("can be only one vote");
			objValidationState.bHasVote = true;
```

**File:** validation.js (L1925-1928)
```javascript
		case "data_feed":
			if (objValidationState.bHasDataFeed)
				return callback("can be only one data feed");
			objValidationState.bHasDataFeed = true;
```

**File:** validation.js (L1954-1964)
```javascript
		case "profile":
			if (objUnit.authors.length !== 1)
				return callback("profile must be single-authored");
			if (objValidationState.bHasProfile)
				return callback("can be only one profile");
			objValidationState.bHasProfile = true;
			// no break, continuing
		case "data":
			if (typeof payload !== "object" || payload === null)
				return callback(objMessage.app+" payload must be object");
			return callback();
```

**File:** definition.js (L1199-1216)
```javascript
			case 'formula':
				var formula = args;
				augmentMessagesOrIgnore(formula, function (err, messages) {
					if (err)
						return cb2(false);
					var trigger = {};
					objUnit.messages.forEach(function (message) {
						if (message.app === 'data' && !trigger.data) // use the first data mesage, ignore the subsequent ones
							trigger.data = message.payload;
					});
					var opts = {
						conn: conn,
						formula: formula,
						messages: messages,
						trigger: trigger,
						objValidationState: objValidationState,
						address: address
					};
```

**File:** test/samples/sending_prepared_objects_through_trigger_data.oscript (L1-15)
```text
{
	messages: [
		{
			if: `{trigger.data.d}`,
			app: 'data',
			payload: `{trigger.data.d}`
		},
		{
			if: `{trigger.data.sub}`,
			app: 'data',
			payload: {
				xx: 66.3,
				sub: `{trigger.data.sub}`
			}
		},
```
