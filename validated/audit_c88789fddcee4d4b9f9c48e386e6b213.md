[1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** external-crates/move/crates/move-abstract-interpreter/src/absint.rs (L149-171)
```rust
        let mut next_block_candidate = cfg.next_block(block_id);
        // propagate postcondition of this block to successor blocks
        for successor_block_id in cfg.successors(block_id) {
            interpreter.visit_successor(successor_block_id)?;
            match inv_map.get_mut(&successor_block_id) {
                Some(next_block_invariant) => {
                    let join_result =
                        interpreter.join(&mut next_block_invariant.pre, &post_state)?;
                    match join_result {
                        JoinResult::Unchanged => {
                            // Pre is the same after join. Reanalyzing this block would produce
                            // the same post
                        }
                        JoinResult::Changed => {
                            next_block_invariant.post = BlockPostCondition::Unprocessed;
                            // If the cur->successor is a back edge, jump back to the beginning
                            // of the loop, instead of the normal next block
                            if cfg.is_back_edge(block_id, successor_block_id) {
                                interpreter.visit_back_edge(block_id, successor_block_id)?;
                                next_block_candidate = Some(successor_block_id);
                                break;
                            }
                        }
```

**File:** external-crates/move/crates/move-abstract-interpreter/src/control_flow_graph.rs (L140-244)
```rust
        // # Loop analysis
        //
        // This section identifies loops in the control-flow graph, picks a back edge and loop head
        // (the basic block the back edge returns to), and decides the order that blocks are
        // traversed during abstract interpretation (reverse post-order).
        //
        // The implementation is based on the algorithm for finding widening points in Section 4.1,
        // "Depth-first numbering" of Bourdoncle [1993], "Efficient chaotic iteration strategies
        // with widenings."
        //
        // NB. The comments below refer to a block's sub-graph -- the reflexive transitive closure
        // of its successor edges, modulo cycles.

        #[derive(Copy, Clone)]
        enum Exploration {
            InProgress,
            Done,
        }

        let mut exploration: Map<I::Index, Exploration> = Map::new();
        let mut stack = vec![I::ENTRY_BLOCK_ID];

        // For every loop in the CFG that is reachable from the entry block, there is an entry in
        // `loop_heads` mapping to all the back edges pointing to it, and vice versa.
        //
        // Entry in `loop_heads` implies loop in the CFG is justified by the comments in the loop
        // below.  Loop in the CFG implies entry in `loop_heads` is justified by considering the
        // point at which the first node in that loop, `F` is added to the `exploration` map:
        //
        // - By definition `F` is part of a loop, meaning there is a block `L` such that:
        //
        //     F - ... -> L -> F
        //
        // - `F` will not transition to `Done` until all the nodes reachable from it (including `L`)
        //   have been visited.
        // - Because `F` is the first node seen in the loop, all the other nodes in the loop
        //   (including `L`) will be visited while `F` is `InProgress`.
        // - Therefore, we will process the `L -> F` edge while `F` is `InProgress`.
        // - Therefore, we will record a back edge to it.
        let mut loop_heads: Map<I::Index, Set<I::Index>> = Map::new();

        // Blocks appear in `post_order` after all the blocks in their (non-reflexive) sub-graph.
        let mut post_order = Vec::with_capacity(blocks.len());

        while let Some(block) = stack.pop() {
            match exploration.entry(block) {
                Entry::Vacant(entry) => {
                    // Record the fact that exploration of this block and its sub-graph has started.
                    entry.insert(Exploration::InProgress);

                    // Push the block back on the stack to finish processing it, and mark it as done
                    // once its sub-graph has been traversed.
                    stack.push(block);

                    for succ in &blocks[&block].successors {
                        match exploration.get(succ) {
                            // This successor has never been visited before, add it to the stack to
                            // be explored before `block` gets marked `Done`.
                            None => stack.push(*succ),

                            // This block's sub-graph was being explored, meaning it is a (reflexive
                            // transitive) predecessor of `block` as well as being a successor,
                            // implying a loop has been detected -- greedily choose the successor
                            // block as the loop head.
                            Some(Exploration::InProgress) => {
                                loop_heads.entry(*succ).or_default().insert(block);
                            }

                            // Cross-edge detected, this block and its entire sub-graph (modulo
                            // cycles) has already been explored via a different path, and is
                            // already present in `post_order`.
                            Some(Exploration::Done) => { /* skip */ }
                        };
                    }
                }

                Entry::Occupied(mut entry) => match entry.get() {
                    // Already traversed the sub-graph reachable from this block, so skip it.
                    Exploration::Done => continue,

                    // Finish up the traversal by adding this block to the post-order traversal
                    // after its sub-graph (modulo cycles).
                    Exploration::InProgress => {
                        post_order.push(block);
                        entry.insert(Exploration::Done);
                    }
                },
            }
        }

        let traversal_order = {
            // This reverse post order is akin to a topological sort (ignoring cycles) and is
            // different from a pre-order in the presence of diamond patterns in the graph.
            post_order.reverse();
            post_order
        };

        // build a mapping from a block id to the next block id in the traversal order
        let traversal_successors = traversal_order
            .windows(2)
            .map(|window| {
                debug_assert!(window.len() == 2);
                (window[0], window[1])
            })
            .collect();
```
