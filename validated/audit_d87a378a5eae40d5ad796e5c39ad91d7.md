This confirms the pattern discrepancy. `PushHandler#process` and `CheckSuiteHandler#process` both scope their work through the base class `Handler#stacks`, which resolves via `Repository.from_github_repo_name(repository_name)` — i.e., they restrict mutation to the repository named in the payload. `StatusHandler#process`, however, does not call `stacks` or `repository_name` at all; it queries `Commit.where(sha: params.sha)` across the entire `commits` table, unscoped by repository, and calls `commit.create_status_from_github!(params)` on every match.### Title
`StatusHandler#process` mutates commit status for any stack sharing a SHA, regardless of which organization's webhook signature authenticated the request - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` looks up commits solely by `sha` across the entire `commits` table, with no scoping to the repository named in the webhook payload, unlike `PushHandler` and `CheckSuiteHandler` which scope through `Handler#stacks`. Because `sha` is derived from git content (tree, parents, author/committer, timestamps) and is not cryptographically bound to any particular repository, an attacker who owns any Shipit-registered repository can produce a commit with an identical SHA to a commit tracked in a victim's stack (e.g. via `git cherry-pick` reproducing identical metadata) and, by sending a `status` webhook signed with their own org's `webhook_secret`, mutate the victim's `Commit`'s status.

### Finding Description
The broken binding: `Shipit.github(organization: repository_owner_from_payload)` (the org whose `webhook_secret` verified the HMAC in `verify_signature`) should equal the org owning the `Stack`/`Commit` being mutated. It does not.

- `WebhooksController#verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-49`) only checks that `request.raw_post` is signed by `Shipit.github(organization: repository_owner)`, where `repository_owner` is read from the attacker-controlled payload (`params.dig('repository','owner','login')`). It has no knowledge of, and does not check, which stack/commit the handler will end up touching.
- `StatusHandler#process` (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`):
  ```ruby
  def process
    Commit.where(sha: params.sha).each do |commit|
      commit.create_status_from_github!(params)
    end
  end
  ```
  This queries `Commit` globally by `sha` only, never calling `Handler#repository_name` or `Handler#stacks` (`app/models/shipit/webhooks/handlers/handler.rb:32-38`), which is the mechanism `PushHandler#process` (`app/models/shipit/webhooks/handlers/push_handler.rb:12-17`) and `CheckSuiteHandler#process` (`app/models/shipit/webhooks/handlers/check_suite_handler.rb:13-17`) use to scope mutations to `Repository.from_github_repo_name(repository_name)&.stacks`.
- Because SHA-1 git commit hashes are computed only from tree/parent/author/committer/message/timestamp content (not repository identity), an attacker can `git cherry-pick` an existing victim commit into their own repo, preserving all inputs to the hash, to produce a byte-identical SHA.
- Attack: attacker registers `evil-org/evil-repo` in Shipit with a legitimately configured `webhook_secret`. They POST `/webhooks` with `X-Github-Event: status`, body `{sha: <shared_sha>, state: 'success', repository: {full_name: 'evil-org/evil-repo', owner: {login: 'evil-org'}}}`, signed with evil-org's own secret. `verify_signature` resolves `Shipit.github(organization: 'evil-org')` and passes, since the signature is valid for evil-org's secret and evil-org's own payload. `StatusHandler.process` then runs `Commit.where(sha: shared_sha)`, which matches the victim's tracked commit row (`shipit_commits(:target)`), and calls `commit.create_status_from_github!(params)`, mutating `victim-org`'s `Commit`'s status via `Status.replicate_from_github!` (`app/models/shipit/status.rb:24-33`).
- Existing guards do not prevent this: `verify_signature` only authenticates that the *sender* controls the named org's secret, not that the SHA belongs to that org's repo; `drop_unhandled_event` and `ExplicitParameters` schema (`requires :sha, String; requires :state, String`) only validate presence/type, not ownership; there is no `subset`/repository-membership validator invoked in this handler.

### Impact Explanation
A successful request causes a `Commit` row belonging to `victim-org/victim-repo` to have a new `Status` created/replicated with attacker-chosen `state`, `description`, `target_url`, and `context`, as if it came from CI for that stack. This is a cross-repository/cross-tenant write triggered by a payload authenticated only for the attacker's own repository — matching the "payload for one repository mutating another's stack/commit" Critical category. Depending on the victim stack's configuration (`stack.ignore_ci?`, blocking statuses, `deployable?`), this status flip can unblock a deploy (`Commit#deployable?`, `app/models/shipit/commit.rb:227-229`) or otherwise falsify CI history, and can be repeated against any SHA the attacker can reproduce (any commit shared/forked/cherry-picked from a public or otherwise accessible history) and against any number of tenants at low cost, since the attacker needs no privileges beyond owning one legitimately registered repo.

### Likelihood Explanation
Preconditions are modest but non-trivial: the attacker must (1) legitimately register a repository in Shipit (own `webhook_secret`), and (2) be able to reproduce an identical SHA for a commit already tracked as a victim's `Commit` — feasible via `git cherry-pick` (or manual commit construction) preserving tree, parents, author, committer, and timestamps exactly, which is realistic for public open-source commits, shared upstream commits, or commits from forks with identical metadata. No GitHub or Shipit secrets belonging to the victim are required at any point. The attack is repeatable at will against any SHA the attacker can reproduce.

### Recommendation
Scope `StatusHandler#process` to the repository named in the payload, mirroring `PushHandler`/`CheckSuiteHandler`: resolve `stacks` via `Handler#stacks`/`repository_name` and restrict the `Commit` lookup to `stacks.flat_map(&:commits).where(sha: params.sha)` (or equivalently `Commit.where(sha: params.sha, stack_id: stacks.select(:id))`), so a status update can only mutate commits belonging to the stack(s) of the repository that authenticated the webhook.

### Proof of Concept
Minitest (e.g. added to `test/controllers/webhooks_controller_test.rb`) with no live GitHub calls:
```ruby
test "status webhook for one repository must not mutate another repository's commit" do
  # Arrange: victim commit already tracked, state != success
  victim_commit = shipit_commits(:target) # belongs to victim's stack, e.g. shipit_stacks(:shipit)
  victim_commit.statuses.destroy_all
  refute_equal 'success', victim_commit.reload.state

  # Configure evil-org with its own webhook_secret, distinct from victim's org secret
  Shipit.stubs(:github).with(organization: 'evil-org').returns(
    Shipit::GitHubApp.new('evil-org', webhook_secret: 'evil-secret')
  )
  # keep victim org's real Shipit.github(organization: 'shopify') behavior untouched

  body = {
    sha: victim_commit.sha,
    state: 'success',
    repository: { full_name: 'evil-org/evil-repo', owner: { login: 'evil-org' } }
  }.to_json
  signature = "sha1=#{OpenSSL::HMAC.hexdigest('sha1', 'evil-secret', body)}"

  request.headers['X-Github-Event'] = 'status'
  request.headers['X-Hub-Signature'] = signature

  post :create, body:, as: :json
  assert_response :ok

  # Assert: victim's commit was mutated despite signature only covering evil-org
  assert_equal 'success', victim_commit.reload.state
end
```
Expected (pre-fix): the assertion `assert_equal 'success', victim_commit.reload.state` passes, proving the divergence — `Shipit.github(organization: 'evil-org')` (the signature-verifying org) ≠ `victim_commit.stack.repository.owner` (the org owning the mutated commit), yet the mutation still occurs.