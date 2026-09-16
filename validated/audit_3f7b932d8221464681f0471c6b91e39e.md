### Title
Full plaintext of decrypted peer/device messages is written to node logs on every message - ([File: device.js])

### Summary
`device.js`'s `decryptPackage()` decrypts every inbound end-to-end encrypted device message (chat messages, pairing data, wallet fund/multisig requests, private-payment chains sent between paired wallets) and then unconditionally writes the fully decrypted plaintext to the process log via `console.log`, exactly the class of bug in CVE-2022-24758 (sensitive data recorded in server logs by default, readable without elevated privilege).

### Finding Description
`decryptPackage()` derives the shared secret, decrypts the AES-GCM ciphertext, and immediately logs the entire decrypted message body in cleartext: [1](#0-0) 
This happens on the normal, non-error code path for every successfully decrypted device message — it is not gated by a debug flag, error condition, or privilege check. Any message that a correspondent (or an attacker who can reach the device-message pipeline, e.g. by pairing or spoofing a hub-relayed message that is decryptable to a peer's own key) sends will have its full JSON payload — including private-payment chain elements (addresses, amounts, blinding factors), pairing secrets, and other wallet-message contents used across `wallet.js`/`device.js` message handling — persisted to the node's console/log output.

### Impact Explanation
Node operators typically capture `console.log` output to disk-based logs (stdout/stderr redirected to log files) for their long-running `ocore`-based node/wallet process. Because the decrypted plaintext of device messages (including private-payment chain data with amounts/blinding factors and pairing/wallet coordination payloads) is written unconditionally to these logs, anyone with read access to the log files (which, per the referenced CVE pattern, do not require root/administrative access) can recover sensitive wallet and private-payment information exchanged between paired devices. This can lead to disclosure of private payment details and facilitate targeted double-spend or fund-tracing attacks against the affected wallet's private chains.

### Likelihood Explanation
Likelihood is high: the logging occurs on the ordinary success path of `decryptPackage()`, triggered by every legitimate device message a paired counterparty sends, and requires no error condition or special timing. Any paired device (or, if message routing is not itself gated, any actor able to get a decryptable package to a target) causes this logging automatically.

### Recommendation
Remove or redact the `console.log("decrypted: "+decrypted_message)` statement in `device.js`, or gate it behind an explicit, disabled-by-default debug flag that developers must intentionally enable, and audit related `console.log` calls that print decrypted device-message contents (e.g., surrounding lines in `decryptPackage`) for the same issue.

### Proof of Concept
1. Pair two wallets (device A and device B) as normal ocore/wallet users.
2. From device B, send any private-payment chain or wallet message to device A (standard wallet.js flow that calls `device.sendMessageToDevice`).
3. On device A's node, observe the process logs: the full decrypted JSON payload (including private payment chain elements with addresses and blinding factors) appears in plaintext via the `console.log("decrypted: "+decrypted_message)` line at [2](#0-1) 
4. Anyone with read access to device A's log files (without needing to compromise its private keys or gain elevated OS privileges) can extract this sensitive private-payment/wallet data.

### Citations

**File:** device.js (L463-466)
```javascript
	breadcrumbs.add("decrypted lengths: "+decrypted1.length+" + "+decrypted2.length);
	var decrypted_message_buf = Buffer.concat([decrypted1, decrypted2]);
	var decrypted_message = decrypted_message_buf.toString("utf8");
	console.log("decrypted: "+decrypted_message);
```
