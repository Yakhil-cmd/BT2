### Title
Path-traversal via `inherit_from` in `DeploySpec::FileSystem#build_config` allows reading files outside the checked-out repository - (File: app/models/shipit/deploy_spec/file_system.rb)

### Summary
`build_config` resolves `inherit_from` with `path.dirname.join(...)` and never verifies the result stays inside `@app_dir`, so a `../../../etc/passwd`-style value lets `read_config` `SafeYAML.load` an arbitrary file on the deploy host and merge its contents into the deploy spec. However, this code only ever runs against a git checkout produced by `StackCommands#with_temporary_working_directory` / `TaskCommands#deploy_spec`, i.e. content committed to a SHA that is `reachable` on the stack's own branch (or the review-stack's PR branch that the *stack itself* already tracks) — not arbitrary attacker-supplied content from an unrelated, unauthenticated PR.

### Finding Description
The broken binding is: for all paths `p` produced inside `build_config`, `p.to_s.start_with?(@app_dir.to_s) == true`. In `app/models/shipit/deploy_spec/file_system.rb:149-160`:
```ruby
def build_config(path, config_obj)
  return config_obj if config_obj.blank? || !config_obj.key?(SHIPIT_CONFIG_INHERIT_FROM_KEY)

  inherits_from_path = path.dirname.join(config_obj.delete(SHIPIT_CONFIG_INHERIT_FROM_KEY))
  if inherits_from_path.exist?
    inherits_config_obj = read_config(inherits_from_path)
    config_obj = inherits_config_obj.deep_merge(config_obj)
    path = inherits_from_path
  end

  build_config(path, config_obj)
end
```
There is indeed no containment check, and `Pathname#join` with a value like `../../../../etc/passwd` will happily escape `@app_dir`, matching the reported flaw exactly. `read_config` (`app/models/shipit/deploy_spec/file_system.rb:162-164`) then calls `SafeYAML.load(path.read)` on whatever path results.

However, `DeploySpec::FileSystem` is never fed attacker-controlled arbitrary content without a corresponding checkout of a real, resolvable commit on a stack the operator already trusts:
- `CacheDeploySpecJob#perform` (`app/jobs/shipit/cache_deploy_spec_job.rb:16-23`) builds the spec from `commands.with_temporary_working_directory(commit: stack.commits.reachable.last, ...)`, i.e. a commit already recorded as reachable on the stack's tracked branch.
- `StackCommands#fetch_deployed_revision` / `#build_cacheable_deploy_spec` and `TaskCommands#deploy_spec` (`lib/shipit/stack_commands.rb:51-65`, `lib/shipit/task_commands.rb:13-15`) likewise operate on a real `git clone`+`checkout` of a commit belonging to the stack (`app/models/shipit/stack.rb`), performed on the Shipit deploy host's own filesystem inside a `Dir.mktmpdir`.
- `EphemeralCommitChecks#run` (`app/models/shipit/ephemeral_commit_checks.rb:14-21`) checks out `@commit`, which is tied to a `Shipit::Commit` record associated with the stack (created via GitHub sync/webhooks for commits Shipit already tracks on that repo/branch, or a review-stack PR head that the operator has configured a review stack app to auto-provision for).

To reach `build_config` with attacker content, the attacker's commit must become `stack.commits.reachable.last` (i.e. be pushed to, or merged toward, the branch the stack tracks) or be the head of a PR that a review-stack configuration has already decided to check out for that specific repository. An unprivileged internet user who merely opens a PR against a repository they do not control, or POSTs to `/webhooks`, cannot make Shipit clone and treat an arbitrary un-trusted branch as `stack.branch`/`commits.reachable` — webhook signature verification (`GitHubApp#verify_webhook_signature`) and the repository/stack scoping in `Stack`/`Commit` models still gate which repo's commits are ever fetched, and PR content from a fork only becomes reachable through this path if the operator has configured review stacks to build from PR heads of that specific repo (an expected, documented capability of review stacks, not a bypass of any check).

### Impact Explanation
The missing containment check is real: within the scope of a repository/branch the Shipit operator has already configured to be checked out and built (a stack's tracked branch, or an explicitly provisioned review stack's PR), whoever can commit `inherit_from: ../../../etc/passwd` (or a path targeting real host secrets, e.g. `../../../../home/deploy/.ssh/id_rsa` or files under the app's `Rails.root`) into their `shipit.yml` can get its contents `deep_merge`d into the effective `deploy.override`/`rollback.override` steps, and — if the target file happens to parse as YAML containing shell fragments an attacker crafted via a symlink or predictable path — could inject/observe unintended content into deploy commands executed by `Command#start`. This is a real defect in `build_config`, but it does not, by itself, grant an *unprivileged* attacker (per the strict definition in this audit: no push access to the branch, no review-stack provisioning right, no maintainer role) a way to make Shipit build a spec from their content in the first place.

### Likelihood Explanation
Exploitability is gated entirely by whether the attacker already has the ability to get a commit checked out as part of a stack's tracked branch or a provisioned review stack — i.e., write/push access to the deploy branch, or merge-queue/review-stack privileges for that repository. Under the audit's attacker model (no session, no API token, no team membership, no maintainer role, only "can open a PR / push to a fork / send webhooks"), there is no demonstrated path that causes an arbitrary un-trusted branch/PR to be checked out and have its `shipit.yml` parsed by `build_config` without the repository/stack already being configured by an operator to build that content (the normal, intended trust boundary for CI/CD config in this and virtually all git-based CI systems).

### Recommendation
Add an explicit containment check in `build_config`, e.g.:
```ruby
inherits_from_path = path.dirname.join(config_obj.delete(SHIPIT_CONFIG_INHERIT_FROM_KEY)).expand_path
unless inherits_from_path.to_s.start_with?(@app_dir.expand_path.to_s)
  raise DeploySpec::Error, "inherit_from must not escape the repository checkout"
end
```
This closes the defense-in-depth gap even though, per the current architecture, `build_config` only ever runs against content the operator has already chosen to check out.

### Proof of Concept
```ruby
# test/models/shipit/deploy_spec/file_system_test.rb
test '#build_config refuses to resolve inherit_from outside @app_dir' do
  Dir.mktmpdir do |root|
    app_dir = Pathname.new(root).join('repo').tap(&:mkpath)
    outside_file = Pathname.new(root).join('outside.yml')
    outside_file.write("deploy:\n  override:\n  - 'cat /etc/passwd'\n")

    shipit_yml = app_dir.join('shipit.yml')
    shipit_yml.write("inherit_from: '../outside.yml'\n")

    stack = shipit_stacks(:shipit)
    spec = Shipit::DeploySpec::FileSystem.new(app_dir, stack)
    spec.stubs(:config_file_path).returns(shipit_yml)

    config_obj = spec.send(:read_config, shipit_yml)
    result_path_will_escape = app_dir.join('shipit.yml').dirname.join('../outside.yml')

    assert_equal false, result_path_will_escape.to_s.start_with?(app_dir.to_s) # binding is broken today
    assert_raises(Shipit::DeploySpec::Error) do
      spec.send(:build_config, shipit_yml, config_obj) # after fix: must raise instead of reading outside_file
    end
  end
end
```
This demonstrates the missing `inherits_from_path.to_s.start_with?(@app_dir.to_s)` check without requiring live GitHub access, confirming the code-level defect while the scoped, real-world impact remains bounded by which branches/PRs an operator's Shipit instance is already configured to check out.