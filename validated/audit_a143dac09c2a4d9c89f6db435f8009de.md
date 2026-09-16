### Title
Unbounded regex scans over attacker-controlled paired-device "text" messages can freeze/crash the receiving wallet - (File: wallet.js)

### Summary
Mattermost's CVE-2024-2446 crashes a victim client because it never bounds the number of `@`-mentions it processes in a single message before rendering/parsing it. The analogous reachable surface in ocore is the handling of the `"text"` device-message subject in `handleMessageFromHub`, where an arbitrary paired correspondent can send a message body of essentially unbounded size/content that is run through several global regex substitutions before being handed to the UI event handler.

### Finding Description
In `wallet.js`, `handleMessageFromHub` processes the `"text"` subject like this: [1](#0-0) 

The only checks performed are: (1) the outer JSON message passed `isTooDeeplyNestedOrHasTooManyNodes(json, 20, 100000)` in the caller, and (2) `ValidationUtils.isNonemptyString(body)`. Neither check bounds the *length* of a string leaf — `isTooDeeplyNestedOrHasTooManyNodes` only counts object/array nodes and recursion depth, treating a string value as a single leaf regardless of its length: [2](#0-1) 

So a correspondent (a paired device — any address a user has ever paired with, which is a broadly reachable, low-privilege relationship in Obyte) can send a `text` message whose `body` is an extremely large string (bounded in practice only by the outer WebSocket payload/message-size limits enforced far upstream in `network.js`/`device.js`, not by any check specific to the `text` payload). That body is then run through four unconditional global regex replacements before being emitted to the wallet UI: [3](#0-2) 

Each of these `.replace(/\(...+?\)/g, '')` calls scans the entire string once per pattern. A message crafted with a very large number of unmatched/nearly-matched opening tokens (e.g. many repetitions of `"(prosaic-contract:"` without a closing `)`, or many short bogus matches) forces the regex engine to attempt a match starting at nearly every character offset, producing quadratic-time behavior over the length of the body for at least one of the four patterns, and this work is repeated four times in series on the same string. On a large enough payload this single synchronous message-processing step can block the JS event loop for a long time, causing the same effect the Mattermost bug describes for its victims: an unresponsive/frozen (in the extreme, watchdog-killed) client, without the sender needing to be anything more than an already-paired correspondent who simply sends one `text` device message.

This mirrors the CVE-2024-2446 bug class exactly: no cap on the amount of pattern-matching work a single message can trigger, letting one authenticated/paired peer degrade or crash the recipient's client.

### Impact Explanation
An attacker who is (or becomes, since pairing itself is attacker-initiated and low-friction) a paired correspondent can cause a victim's wallet process to hang or become unresponsive by sending a single crafted `text` message. This is a denial-of-service against the victim's client — it does not by itself cause double-spend, fund loss, or consensus divergence, but it can freeze wallet operation (e.g., during a time-sensitive spend, arbitration deadline, or AA trigger response), degrading availability of the wallet exactly as described in the CVE's impact ("crash the client applications of other users via large, crafted messages").

### Likelihood Explanation
Reaching this code path requires only being an existing (or newly-paired) correspondent device — no special role, funds, or privileged trust level is required beyond normal pairing, which is designed to be easy and is routinely done with unknown counterparties (e.g., in commerce/bot use). Constructing a body with many repeated unmatched substrings is trivial. The main uncertainty is the exact upper bound on message/body size enforced elsewhere in the pipeline (e.g. WebSocket `maxPayload`/hub relay limits in `network.js`), which was not fully confirmed in this pass; if that bound is large (which is typical, to accommodate encrypted device messages, contracts, attestation payloads, etc.), the attack is straightforward to reach.

### Recommendation
- Impose an explicit maximum length on `body` for the `"text"` subject in `wallet.js` before running any regex against it (reject or truncate messages beyond, e.g., a few KB, consistent with normal chat use).
- Replace the four sequential global `.replace()` calls with a single pass (one combined regex or a linear-scan tokenizer) to avoid multiplying the cost by the number of patterns.
- Consider bounding the number of matches processed per message (analogous to Mattermost's own fix of capping mentions), so a message with a huge number of embedded contract/dispute tokens cannot force unbounded work regardless of overall message length limits.

### Proof of Concept
1. Pair with a victim device (or use an existing pairing).
2. Send a `"text"` justsaying/device message whose `body` is, e.g., 5–10 MB of `"(prosaic-contract:"` repeated without any closing `)`, followed by ordinary text.
3. On receipt, `handleMessageFromHub` invokes the four `.replace(/\(...+?\)/g, '')` calls in sequence on the full body in `wallet.js` (lines 105-109) before emitting the `"text"` event; the synchronous regex scanning blocks the event loop, freezing the victim's wallet UI/process for a duration proportional to the crafted payload size, reproducing the "crash via large, crafted message" effect described in CVE-2024-2446.

### Citations

**File:** wallet.js (L101-113)
```javascript
			case "text":
				message_counter++;
				if (!ValidationUtils.isNonemptyString(body))
					return callbacks.ifError("text body must be string");
				body = body
					.replace(/\(prosaic-contract:.+?\)/g, '')
					.replace(/\(arbiter-contract-offer:.+?\)/g, '')
					.replace(/\(arbiter-contract-event:.+?\)/g, '')
					.replace(/\(arbiter-dispute:.+?\)/g, '');
				// the wallet should have an event handler that displays the text to the user
				eventBus.emit("text", from_address, body, message_counter);
				callbacks.ifOk();
				break;
```

**File:** string_utils.js (L260-284)
```javascript
function isTooDeeplyNestedOrHasTooManyNodes(obj, depthLimit = 100, nodesLimit = 10000) {
	let nodeCount = 0;

	function check(variable, depth){
		if (depth > depthLimit || nodeCount > nodesLimit)
			return true;
		if (variable === null || typeof variable !== "object")
			return false;
		if (Array.isArray(variable)) {
			nodeCount += variable.length;
			for (let v of variable)
				if (check(v, depth + 1))
					return true;
		}
		else {
			nodeCount += Object.keys(variable).length;
			for (let key in variable)
				if (check(variable[key], depth + 1))
					return true;
		}
		return false;
	}

	return check(obj, 1);
}
```
