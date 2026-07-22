Looking at the Astaria bug class — **an unclamped/unbounded parameter that should be validated against a system invariant but isn't** — I need to find the Metric OMM analog where a pool admin can set a fee parameter beyond the factory's intended cap.

Let me check the `setBinAdditionalFees` path and the factory's cap enforcement.