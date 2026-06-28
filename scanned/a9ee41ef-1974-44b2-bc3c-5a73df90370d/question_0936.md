# Q936: EIP-4844 parsing zero-address edge in chain id handling for the 4844 type

## Question
Can an attacker hit a zero-address or empty-field edge through `submit()` / `submit_with_args()` with an EIP-4844 transaction path so that chain id handling for the 4844 type routes the transaction differently from the rest of the engine and causes Insolvency?

## Target
- File/function: `engine-transactions/src/eip_4844.rs` -> `chain id handling for the 4844 type`
- Entrypoint: `submit()` / `submit_with_args()` with an EIP-4844 transaction path
- Attacker controls: typed transaction bytes, blob-related fee fields, calldata, recipient/create choice, signature values, and replay timing
- Exploit idea: target the exact empty or zero-valued branch controlled by the subtarget.
- Invariant to test: EIP-4844 parsing must not let blob-style fee or envelope fields desynchronize gas accounting from execution intent
- Expected Immunefi impact: Insolvency
- Fast validation: Test empty recipient, zero sender-derived branch, and zero-value variants and assert route selection and state updates stay canonical. add parser tests plus local execution tests that mutate typed-envelope and fee fields and check sender, fee charge, refund, and resulting state
