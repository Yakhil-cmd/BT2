No vulnerability found for this question.

The Sequelize advisory concerns a Node.js/npm ORM library's improper filtering of query operators, but this repository contains no Sequelize dependency at all [1](#0-0)  — the only SQL usage found is in `substrate/frame/revive/rpc` (an Ethereum-JSON-RPC compatibility shim for pallet-revive), implemented in Rust with `sqlx` and consistently using parameterized/bound queries (`push_bind`, `sqlx::query!` with `$1` placeholders) rather than any dynamic query-object filtering mechanism analogous to Sequelize's operator injection issue [2](#0-1) . There is no user-facing extrinsic, XCM message, or contract call path that feeds attacker-controlled input into these SQL queries — they are internal indexing/query-serving logic for RPC responses, not consensus-critical runtime state, and all bound parameters are typed/structured (hashes, block numbers) rather than raw filter objects [3](#0-2) . No credible FRAME/XCM/pallet analog to Sequelize's improper input filtering was found in this codebase.

### Citations

**File:** substrate/frame/revive/rpc/src/receipt_provider.rs (L671-679)
```rust
			let mut query_builder = QueryBuilder::<Sqlite>::new(
				"INSERT OR REPLACE INTO transaction_hashes (transaction_hash, block_hash, transaction_index) ",
			);
			query_builder.push_values(chunk, |mut row, (_, receipt)| {
				row.push_bind(receipt.transaction_hash.as_ref() as &[u8])
					.push_bind(substrate_hash_ref)
					.push_bind(receipt.transaction_index.as_u32() as i32);
			});
			query_builder.build().execute(&mut *db_tx).await?;
```

**File:** substrate/frame/revive/rpc/src/receipt_provider.rs (L731-798)
```rust
		let mut qb = QueryBuilder::<Sqlite>::new("SELECT logs.* FROM logs WHERE 1=1");
		let filter = filter.unwrap_or_default();

		match filter.block_option {
			FilterBlockOption::AtBlockHash(hash) => {
				qb.push(" AND block_hash = ").push_bind(hash.as_slice().to_vec());
			},
			FilterBlockOption::Range { from_block, to_block } => {
				let from_block =
					OptionFuture::from(from_block.map(&resolve_block_number)).await.transpose()?;
				let to_block =
					OptionFuture::from(to_block.map(&resolve_block_number)).await.transpose()?;

				// Read the latest block *after* resolving the tags.
				let latest_block = U256::from(self.block_provider.latest_block_number().await);

				match (from_block, to_block) {
					(Some(block), _) | (_, Some(block)) if block > latest_block => {
						anyhow::bail!("block number exceeds latest block");
					},
					(Some(from_block), Some(to_block)) if from_block > to_block => {
						anyhow::bail!("invalid block range params");
					},
					(Some(from_block), Some(to_block)) if from_block == to_block => {
						qb.push(" AND block_number = ").push_bind(from_block.as_u64() as i64);
					},
					(Some(from_block), Some(to_block)) => {
						qb.push(" AND block_number BETWEEN ")
							.push_bind(from_block.as_u64() as i64)
							.push(" AND ")
							.push_bind(to_block.as_u64() as i64);
					},
					(Some(from_block), None) => {
						qb.push(" AND block_number >= ").push_bind(from_block.as_u64() as i64);
					},
					(None, Some(to_block)) => {
						qb.push(" AND block_number <= ").push_bind(to_block.as_u64() as i64);
					},
					(None, None) => {
						qb.push(" AND block_number = ").push_bind(latest_block.as_u64() as i64);
					},
				}
			},
		}

		if !filter.address.is_empty() {
			qb.push(" AND address IN (");
			let mut separated = qb.separated(", ");
			for addr in filter.address {
				separated.push_bind(addr.as_slice().to_vec());
			}
			separated.push_unseparated(")");
		}

		for (i, topic) in filter.topics.into_iter().enumerate() {
			if topic.is_empty() {
				continue;
			}

			qb.push(format_args!(" AND topic_{i} IN ("));
			let mut separated = qb.separated(", ");
			for hash in topic {
				separated.push_bind(hash.as_slice().to_vec());
			}
			separated.push_unseparated(")");
		}

		qb.push(" LIMIT ").push_bind(MAX_LOG_RESULTS as i64);
```

**File:** substrate/frame/revive/rpc/src/receipt_provider.rs (L844-860)
```rust
	pub async fn receipts_count_per_block(&self, block_hash: &H256) -> Option<usize> {
		let block_hash = block_hash.as_ref();
		let row = query!(
			r#"
            SELECT COUNT(*) as count
            FROM transaction_hashes
            WHERE block_hash = $1
            "#,
			block_hash
		)
		.fetch_one(&self.db_ctx.pool)
		.await
		.ok()?;

		let count = row.count as usize;
		Some(count)
	}
```
