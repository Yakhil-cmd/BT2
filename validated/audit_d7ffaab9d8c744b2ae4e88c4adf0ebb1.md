Based on my investigation, agave's replay protection mechanisms are distinct from S3QL's `checksum_basic_mapping` bug class and are properly reachable-but-guarded against the analogous attack pattern:

- Transaction age/replay validation uses `BlockhashQueue::get_hash_info_if_valid` <cite repo="Camomtat/agave--021" path="accounts-db/src/blockhash_queue.rs" start="97"