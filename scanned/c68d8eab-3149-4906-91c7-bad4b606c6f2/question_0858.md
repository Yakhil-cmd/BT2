# Q858: EIP-4844 parsing gas floor gap at sender recovery for 4844 transactions

## Question
Can an attacker use `submit()` / `submit_with_args()` with an EIP-4844 transaction path so that sender recovery for 4844 transactions enforces too little work relative to the real execution path, enabling underpriced execution that drains relayer or protocol balances and causes Temporary freezing of funds?

## Target
- File/function: `engine-transactions/src/eip_4844.rs` -> `sender recovery for 4844 transactions`
- Entrypoint: `submit()` / `submit_with_args()` with an EIP-4844 transaction path
- Attacker controls: typed transaction bytes, blob-related fee fields, calldata, recipient/create choice, signature values, and replay timing
- Exploit idea: undercharge work by targeting the floor or intrinsic-gas assumption baked into the subtarget.
- Invariant to test: EIP-4844 parsing must not let blob-style fee or envelope fields desynchronize gas accounting from execution intent
- Expected Immunefi impact: Temporary freezing of funds
- Fast validation: Measure actual work against charged gas on crafted calldata and access-list sizes, then assert no path underpays for execution. add parser tests plus local execution tests that mutate typed-envelope and fee fields and check sender, fee charge, refund, and resulting state
