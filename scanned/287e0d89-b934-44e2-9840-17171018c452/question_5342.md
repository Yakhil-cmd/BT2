# Q5342: submit promise resume data with yield id async receipt lifecycle

## Question

What can an unprivileged user do by submitting transactions, deploying contracts, calling methods, and creating promise receipts so that `submit_promise_resume_data_with_yield_id` in `runtime/runtime/src/ext.rs` processes yield/resume payloads, promise dependencies, delayed receipts, instant receipts, and timeout heights along the runtime state transition path? User controls yield/resume payloads, promise dependencies, delayed receipts, instant receipts, and timeout heights -> `submit_promise_resume_data_with_yield_id` processes that value during postponed receipt storage, data receipt delivery, yield timeout, resume handling, and receipt cleanup -> the asynchronous receipts have a single lifecycle state and cannot be resumed, timed out, refunded, or executed twice invariant might break -> potential in-scope impact is contract execution flow corruption, replay, or balance manipulation under the NEAR HackenProof scope. Exploit hypothesis: a user-controlled timing/order edge can make this code transition an async receipt through two terminal states, violating the actual protocol invariant that asynchronous receipts have a single lifecycle state and cannot be resumed, timed out, refunded, or executed twice.

## Target

- File/function: runtime/runtime/src/ext.rs:421::submit_promise_resume_data_with_yield_id
- Entrypoint: signed transaction submitted through public RPC and applied by runtime/runtime/src/lib.rs::Runtime::apply
- User-controlled input: yield/resume payloads, promise dependencies, delayed receipts, instant receipts, and timeout heights
- Attack path: User controls yield/resume payloads, promise dependencies, delayed receipts, instant receipts, and timeout heights -> public entrypoint reaches `submit_promise_resume_data_with_yield_id` -> postponed receipt storage, data receipt delivery, yield timeout, resume handling, and receipt cleanup handles the value -> invariant failure could produce contract execution flow corruption, replay, or balance manipulation
- Security invariant: asynchronous receipts have a single lifecycle state and cannot be resumed, timed out, refunded, or executed twice
- Expected bounty impact: contract execution flow corruption, replay, or balance manipulation
- Fast validation approach: create contracts that interleave yield, resume, timeout, callbacks, and delayed queues, then assert every receipt ID has one terminal outcome
