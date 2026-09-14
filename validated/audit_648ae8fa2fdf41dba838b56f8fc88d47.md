No vulnerability found for this question.

The zip-bomb / unbounded-decompression bug class in MarkUs maps in Agave only to archive-unpacking paths for snapshots and genesis archives (e.g., `hardened_unpack::unpack_archive` in [1](#0-0) , which already enforces `apparent_limit_size`, `actual_limit_size`, and `limit_count` and is only invoked on operator-supplied/local snapshot and genesis files via `verify_and_unarchive_snapshots` and `unpack_genesis_archive` in [2](#0-1) ) and to the install-tool release archive extraction in [3](#0-2) . None of these are reachable from a single unprivileged submitted transaction — they are operator-only/snapshot paths explicitly excluded by scope. Transaction-processing account data has hard, transaction-signer-independent size bounds (`MAX_PERMITTED_DATA_LENGTH`, `loaded_accounts_bytes` compute-budget limits, e.g. [4](#0-3) ) and involves no unbounded decompression of attacker-controlled data, so there is no reachable analog to the MarkUs zip-bomb DoS.

### Citations

**File:** snapshots/src/hardened_unpack.rs (L88-160)
```rust
fn unpack_archive<'a, C>(
    input: impl Read,
    mut file_creator: Box<dyn FileCreator + '_>,
    apparent_limit_size: u64,
    actual_limit_size: u64,
    limit_count: u64,
    mut entry_checker: C, // checks if entry is valid
) -> Result<()>
where
    C: FnMut(&[&str], tar::EntryType) -> UnpackPath<'a>,
{
    let mut apparent_total_size: u64 = 0;
    let mut actual_total_size: u64 = 0;
    let mut total_count: u64 = 0;

    let mut total_entries = 0;
    let mut open_dirs = Vec::new();

    let mut archive = Archive::new(input);
    for entry in archive.entries()? {
        let entry = entry?;
        let path = entry.path()?;
        let path_str = path.display().to_string();

        // Although the `tar` crate safely skips at the actual unpacking, fail
        // first by ourselves when there are odd paths like including `..` or /
        // for our clearer pattern matching reasoning:
        //   https://docs.rs/tar/0.4.26/src/tar/entry.rs.html#371
        let parts = path
            .components()
            .map(|p| match p {
                CurDir => Ok("."),
                Normal(c) => c.to_str().ok_or(()),
                _ => Err(()), // Prefix (for Windows) and RootDir are forbidden
            })
            .collect::<std::result::Result<Vec<_>, _>>();

        // Reject old-style BSD directory entries that aren't explicitly tagged as directories
        let legacy_dir_entry =
            entry.header().as_ustar().is_none() && entry.path_bytes().ends_with(b"/");
        let kind = entry.header().entry_type();
        let reject_legacy_dir_entry = legacy_dir_entry && (kind != Directory);
        let (Ok(parts), false) = (parts, reject_legacy_dir_entry) else {
            return Err(UnpackError::Archive(format!(
                "invalid path found: {path_str:?}"
            )));
        };

        let unpack_dir = match entry_checker(parts.as_slice(), kind) {
            UnpackPath::Invalid => {
                return Err(UnpackError::Archive(format!(
                    "extra entry found: {:?} {:?}",
                    path_str,
                    entry.header().entry_type(),
                )));
            }
            UnpackPath::Ignore => {
                continue;
            }
            UnpackPath::Valid(unpack_dir) => unpack_dir,
        };

        apparent_total_size = checked_total_size_sum(
            apparent_total_size,
            entry.header().size()?,
            apparent_limit_size,
        )?;
        actual_total_size = checked_total_size_sum(
            actual_total_size,
            entry.header().entry_size()?,
            actual_limit_size,
        )?;
        total_count = checked_total_count_increment(total_count, limit_count)?;
```

**File:** snapshots/src/unarchive.rs (L87-115)
```rust
pub fn unpack_genesis_archive(
    archive_filename: &Path,
    destination_dir: &Path,
    max_genesis_archive_unpacked_size: u64,
) -> Result<(), UnpackError> {
    log::info!("Extracting {archive_filename:?}...");
    let extract_start = Instant::now();

    fs::create_dir_all(destination_dir)?;
    let tar_bz2 = fs::File::open(archive_filename)?;
    let tar = BzDecoder::new(BufReader::new(tar_bz2));
    let file_creator = file_creator(
        0, /* don't provide memlock budget (forces sync IO), since genesis archives are small */
        &IoSetupState::default(),
        |file_info| Some(file_info.file),
    )?;
    hardened_unpack::unpack_genesis(
        tar,
        file_creator,
        destination_dir,
        max_genesis_archive_unpacked_size,
    )?;
    log::info!(
        "Extracted {:?} in {:?}",
        archive_filename,
        Instant::now().duration_since(extract_start)
    );
    Ok(())
}
```

**File:** install/src/command.rs (L148-177)
```rust
/// Extracts the release archive into the specified directory
fn extract_release_archive(
    archive: &Path,
    extract_dir: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    use {bzip2::bufread::BzDecoder, tar::Archive};

    let progress_bar = new_spinner_progress_bar();
    progress_bar.set_message(format!("{PACKAGE}Extracting..."));

    if extract_dir.exists() {
        let _ = fs::remove_dir_all(extract_dir);
    }

    let tmp_extract_dir = extract_dir.with_file_name("tmp-extract");
    if tmp_extract_dir.exists() {
        let _ = fs::remove_dir_all(&tmp_extract_dir);
    }
    fs::create_dir_all(&tmp_extract_dir)?;

    let tar_bz2 = File::open(archive)?;
    let tar = BzDecoder::new(BufReader::new(tar_bz2));
    let mut release = Archive::new(tar);
    release.unpack(&tmp_extract_dir)?;

    fs::rename(&tmp_extract_dir, extract_dir)?;

    progress_bar.finish_and_clear();
    Ok(())
}
```

**File:** compute-budget-instruction/src/instructions_processor.rs (L320-336)
```rust
        // Assert when set_loaded_accounts_data_size_limit presents,
        // budget is set with data_size
        let data_size = 1;
        let expected_result = Ok(ComputeBudgetLimits {
            compute_unit_limit: DEFAULT_INSTRUCTION_COMPUTE_UNIT_LIMIT
                + MAX_BUILTIN_ALLOCATION_COMPUTE_UNIT_LIMIT,
            loaded_accounts_bytes: NonZeroU32::new(data_size).unwrap(),
            ..ComputeBudgetLimits::default()
        });
        test!(
            &[
                ComputeBudgetInstruction::set_loaded_accounts_data_size_limit(data_size),
                Instruction::new_with_bincode(Pubkey::new_unique(), &0_u8, vec![]),
            ],
            expected_result,
            &FeatureSet::default()
        );
```
