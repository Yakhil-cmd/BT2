[1](#0-0)

### Citations

**File:** crates/sui-snapshot/src/reader.rs (L28-34)
```rust
use sui_core::authority::AuthorityStore;
use sui_core::authority::authority_store_tables::{AuthorityPerpetualTables, LiveObject};
use sui_futures::stream::TrySpawnStreamExt;
use sui_storage::blob::{Blob, BlobEncoding};
use sui_storage::object_store::http::HttpDownloaderBuilder;
use sui_storage::object_store::util::{copy_files, path_to_filesystem};
use sui_storage::object_store::{ObjectStoreGetExt, ObjectStoreListExt, ObjectStorePutExt};
```
