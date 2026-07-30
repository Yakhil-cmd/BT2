### Title
Global (non-chain-scoped) `isTransferProcessed` nonce mapping causes cross-chain collision and permanent fund lock - (File: `bridge/evm/contracts/SuiBridge.sol`, `bridge/evm/contracts/utils/MessageVerifier.sol`)

### Summary
The EVM-side finalization of Sui bridge token transfers deduplicates finalized messages using a nonce key that omits the source chain identity, unlike the recommended dedup pattern in the external report ("hashDeposit(sourceChain, blockHash, txIndex, logIndex)"). Because `BridgeConfig` explicitly supports multiple independent source chains, and each source chain assigns its own sequential nonce, colliding `(sourceChain, nonce)` pairs from two different chains will cause the second, legitimate transfer to be permanently rejected as "already processed," even though it was never actually finalized. The already-escrowed/burned source-side tokens can never be claimed on the destination chain.

### Finding Description
`transferBridgedTokensWithSignatures`/`transferBridgedTokensWithSignaturesV2` guard against replay with:
```solidity
require(!isTransferProcessed[message.nonce], "SuiBridge: Message already processed");
...
isTransferProcessed[message.nonce] = true;
``` [1](#0-0) 

`isTransferProcessed` is a bare `mapping(uint64 => bool)` indexed only by `message.nonce`, with no source-chain component in the key.

Critically, `MessageVerifier`'s shared modifier explicitly skips the per-message-type nonce validation/incrementing for `TOKEN_TRANSFER` messages:
```solidity
if (messageType != BridgeUtils.TOKEN_TRANSFER) {
    require(message.chainID == committee.config().chainID(), "MessageVerifier: Invalid chain ID");
    require(message.nonce == nonces[message.messageType], "MessageVerifier: Invalid nonce");
    nonces[message.messageType]++;
}
``` [2](#0-1) 

So for TOKEN_TRANSFER, the only replay protection is the global `isTransferProcessed[message.nonce]` flag, keyed purely on nonce, not on `message.chainID`.

`BridgeConfig.initialize` accepts an arbitrary array of `_supportedChains`, confirming the bridge is designed to accept token transfer messages originating from multiple distinct source chains simultaneously:
```solidity
for (uint8 i; i < _supportedChains.length; i++) {
    require(_supportedChains[i] != _chainID, "BridgeConfig: Cannot support self");
    supportedChains[_supportedChains[i]] = true;
}
``` [3](#0-2) 

Each source chain's Move-side bridge module assigns nonces independently and sequentially per message type (see `token_transfer_records` keyed by `message::create_key(source_chain, message_types::token(), bridge_seq_num)` on the Sui side, which correctly scopes by `source_chain`): [4](#0-3) 

Since nonce sequences on each independently-supported source chain both start at 0 and increment by 1 per transfer, a colliding `(nonceA == nonceB)` across two different supported source chains is essentially guaranteed to occur early in the bridge's operation (e.g., both chains' first transfer uses nonce 0). Once chain A's nonce-0 transfer is finalized on the EVM contract, `isTransferProcessed[0] = true` is set globally. Any later legitimate, correctly-signed message from chain B with `nonce == 0` will be rejected by `require(!isTransferProcessed[message.nonce])` forever — even though chain B's transfer was never actually processed. This is the analog of the report's root cause: "The consumed key omits source chain, block, log index, nonce, or token," causing wrong/ambiguous uniqueness semantics.

### Impact Explanation
The affected user has already had their tokens escrowed/burned on the Move-side bridge (`send_token_internal` burns the coin and stores the pending record before the EVM finalization call is ever made) [5](#0-4) , so the finalization step on the EVM destination chain is the only path to receive the corresponding funds. Because the `isTransferProcessed` flag is falsely already `true` due to a same-nonce transfer from a different source chain, the legitimate transfer can never be finalized on the destination chain — this is a permanent, unrecoverable loss/lock of the user's bridged funds, which the given HackenProof scope explicitly allows as a High/Medium impact class ("permanent fund lock").

### Likelihood Explanation
This does not require any malicious bridge authority, validator, or governance action — it is triggered purely by normal, unprivileged relaying of two legitimately-signed messages from two different, both intentionally-supported source chains. Given nonces on each chain start at 0 and increment sequentially, the collision condition (`nonceA == nonceB` while `chainA != chainB`) is close to certain to occur in practice as soon as more than one source chain is actively bridging token transfers to the same destination `SuiBridge` deployment, making this a realistically reachable, non-theoretical scenario under the current multi-chain-supporting `BridgeConfig` design.

### Recommendation
Scope the destination-side dedup key to include the source chain identity, matching the Move-side `message::create_key(source_chain, message_types::token(), bridge_seq_num)` pattern already used correctly in `bridge.move`:
```solidity
mapping(uint8 chainID => mapping(uint64 nonce => bool)) isTransferProcessed;
...
require(!isTransferProcessed[message.chainID][message.nonce], "SuiBridge: Message already processed");
...
isTransferProcessed[message.chainID][message.nonce] = true;
```
Add regression tests that finalize transfers with the same nonce from two different supported source chains and assert both succeed independently.

### Proof of Concept
1. Deploy `SuiBridge`/`SuiBridgeV2` with `BridgeConfig` configured to support two source chains, e.g. chain `0` (Sui mainnet) and chain `1` (another supported chain), as allowed by `BridgeConfig.initialize`'s `_supportedChains` array [6](#0-5) .
2. User A deposits on source chain 0; the Move bridge assigns `bridge_seq_num = 0` and produces a committee-signed `TOKEN_TRANSFER` message with `chainID = 0, nonce = 0`.
3. User B independently deposits on source chain 1; the Move bridge on that chain likewise assigns `bridge_seq_num = 0`, producing a committee-signed message with `chainID = 1, nonce = 0`.
4. Anyone calls `transferBridgedTokensWithSignatures(sigsA, messageA)` — succeeds, sets `isTransferProcessed[0] = true` [1](#0-0) .
5. Anyone then calls `transferBridgedTokensWithSignatures(sigsB, messageB)` with User B's independently and validly-signed message — this reverts with `"SuiBridge: Message already processed"` because `isTransferProcessed[0]` is already `true`, despite User B's transfer never being executed. User B's tokens, already burned/escrowed on source chain 1, are now permanently unclaimable on the destination chain.

### Citations

**File:** bridge/evm/contracts/SuiBridge.sol (L64-92)
```text
        // verify that message has not been processed
        require(!isTransferProcessed[message.nonce], "SuiBridge: Message already processed");

        IBridgeConfig config = committee.config();

        BridgeUtils.TokenTransferPayload memory tokenTransferPayload =
            BridgeUtils.decodeTokenTransferPayload(message.payload);

        // verify target chain ID is this chain ID
        require(
            tokenTransferPayload.targetChain == config.chainID(), "SuiBridge: Invalid target chain"
        );

        // convert amount to ERC20 token decimals
        uint256 erc20AdjustedAmount = BridgeUtils.convertSuiToERC20Decimal(
            IERC20Metadata(config.tokenAddressOf(tokenTransferPayload.tokenID)).decimals(),
            config.tokenSuiDecimalOf(tokenTransferPayload.tokenID),
            tokenTransferPayload.amount
        );

        _transferTokensFromVault(
            message.chainID,
            tokenTransferPayload.tokenID,
            tokenTransferPayload.recipientAddress,
            erc20AdjustedAmount
        );

        // mark message as processed
        isTransferProcessed[message.nonce] = true;
```

**File:** bridge/evm/contracts/utils/MessageVerifier.sol (L38-50)
```text
        // verify message type
        require(message.messageType == messageType, "MessageVerifier: message does not match type");
        // verify signatures
        committee.verifySignatures(signatures, message);
        // increment message type nonce
        if (messageType != BridgeUtils.TOKEN_TRANSFER) {
            // verify chain ID
            require(
                message.chainID == committee.config().chainID(), "MessageVerifier: Invalid chain ID"
            );
            require(message.nonce == nonces[message.messageType], "MessageVerifier: Invalid nonce");
            nonces[message.messageType]++;
        }
```

**File:** bridge/evm/contracts/BridgeConfig.sol (L29-58)
```text
    function initialize(
        address _committee,
        uint8 _chainID,
        address[] memory _supportedTokens,
        uint64[] memory _tokenPrices,
        uint8[] memory _tokenIds,
        uint8[] memory _suiDecimals,
        uint8[] memory _supportedChains
    ) external initializer {
        __CommitteeUpgradeable_init(_committee);
        require(
            _supportedTokens.length == _tokenPrices.length, "BridgeConfig: Invalid token prices"
        );
        require(
            _supportedTokens.length == _tokenIds.length, "BridgeConfig: Invalid token IDs"
        );
        require(
            _supportedTokens.length == _suiDecimals.length, "BridgeConfig: Invalid Sui decimals"
        );

        for (uint8 i; i < _tokenIds.length; i++) {
            // `is_native` is hardcoded to `true` because we only support Eth native tokens
            // at the moment. This needs to change when we support tokens native on other chains.
            supportedTokens[_tokenIds[i]] = Token(_supportedTokens[i], _suiDecimals[i], true);
        }

        for (uint8 i; i < _supportedChains.length; i++) {
            require(_supportedChains[i] != _chainID, "BridgeConfig: Cannot support self");
            supportedChains[_supportedChains[i]] = true;
        }
```

**File:** crates/sui-framework/packages/bridge/sources/bridge.move (L483-496)
```text
    let inner = load_inner(bridge);
    let key = message::create_key(
        source_chain,
        message_types::token(),
        bridge_seq_num,
    );

    if (!inner.token_transfer_records.contains(key)) {
        return option::none()
    };

    let record = &inner.token_transfer_records[key];
    record.verified_signatures
}
```

**File:** crates/sui-framework/packages/bridge/sources/bridge.move (L610-630)
```text
fun send_token_internal<T>(
    inner: &mut BridgeInner,
    target_chain: u8,
    token: Coin<T>,
    message: BridgeMessage,
) {
    assert!(!inner.paused, EBridgeUnavailable);
    assert!(chain_ids::is_valid_route(inner.chain_id, target_chain), EInvalidBridgeRoute);

    // burn / escrow token, unsupported coins will fail in this step
    inner.treasury.burn(token);

    // Store pending bridge request
    inner
        .token_transfer_records
        .push_back(
            message.key(),
            BridgeRecord {
                message,
                verified_signatures: option::none(),
                claimed: false,
```
