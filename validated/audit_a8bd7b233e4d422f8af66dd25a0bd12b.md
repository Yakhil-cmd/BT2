### Title
Cross-repository status forgery via unscoped `sha` lookup in `StatusHandler#process` - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` resolves target commits with `Commit.where(sha: params.sha)` with no constraint tying the match to the `repository`/`stack` named in the webhook payload. Any organization that legitimately owns a webhook signature for its own tracked repo can therefore write a `Status` row onto a `Commit` belonging to a *different* stack/organization, as long as that other stack happens to contain a `Commit` record with the same `sha` (trivially true for shared git ancestry, e.g. forks/mirrors of a public repo, since a git commit object's SHA-1 is a deterministic hash of byte-identical content that anyone with read access to the source repo can reproduce).

### Finding Description
The intended binding is: `payload.repository.full_name == commit.stack.repository.full_name` (the org that signed/authenticated the webhook must be the org that owns the commit being mutated). In code:

- `WebhooksController#verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-49`) resolves `Shipit.github(organization: repository_owner)` from the payload and checks the HMAC signature against **that org's own `webhook_secret`**. This proves only that the request came from *some* GitHub App installation the operator configured — it proves nothing about which `Commit`/`Stack` rows the payload is allowed to touch.
- `StatusHandler#process` (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`) then does:
```ruby
Commit.where(sha: params.sha).each do |commit|
  commit.create_status_from_github!(params)
end
```
There is no `stack_id`/`repository` filter here at all — every `Commit` row in the entire database sharing that `sha`, across every stack and every organization, gets a new `Status` (`app/models/shipit/commit.rb:165-169`, `add_status`), with attacker-chosen `state`, `context`, `description`, `target_url`.

So the actual enforced equality is `payload.repository.full_name == <org tied to the signing secret>`, never `== commit.stack.repository.full_name`. These two can diverge whenever the same `sha` exists as a `Commit` row under two different stacks (fork/mirror scenario, or any repo importing the same commit object — trivial to reproduce since SHA-1 of a git commit is a pure function of tree+parents+author+committer+message, all of which are readable from any public repo and reproducible byte-for-byte in an attacker-controlled repo).

Exploit flow:
1. Victim stack `V` (org `acme`, `continuous_deployment: true`) has `Commit` row `C` with `sha = S`, currently not `deployable?` (pending/failing real CI), and has an active `Task` running.
2. Attacker legitimately administers repo/org `attacker-org`, which is also onboarded on the same Shipit instance and has its own valid `webhook_secret` (a normal, unprivileged tenant relationship — not a Shipit operator).
3. Attacker reproduces the byte-identical git commit object for sha `S` in their own repo (fork of the public upstream, or `git commit-tree` replay) and gets it synced into their own stack, creating a `Commit` row with the same `sha = S` under `attacker-org`'s stack.
4. Attacker's own CI (or a raw POST if their webhook secret happens to be unset/known to them, which is a legitimate credential in their own tenant) sends a genuinely-signed `status` webhook for `sha: S, state: "success"` from `attacker-org`.
5. `verify_signature` passes (signed correctly for `attacker-org`). `StatusHandler#process` matches **all** `Commit` rows with `sha == S`, including victim's `C`, and calls `commit.create_status_from_github!(params)` on it — writing a new `Status(stack_id: V.id, state: "success", context: attacker_chosen)` onto the victim's commit.
6. This flips `C.deployable?` (`app/models/shipit/commit.rb:227-229`) depending on aggregation in `Status::Group#select_significant_status` (`app/models/shipit/status/group.rb:75-83`) — since statuses are deduplicated `by(&:context)` (`group.rb:27`), an attacker who picks a `context` matching (or not yet present) on the real commit can add/replace the significant status.
7. `Stack#next_expected_commit_to_deploy` (`app/models/shipit/stack.rb:332-342`) and `Stack#next_commit_to_deploy`/`deployable_commits` (`stack.rb:235-243`) are recomputed using this poisoned `deployable?`. `Commit#active?` (`app/models/shipit/commit.rb:221-225`) only excludes commits inside the *currently running* task, so it does not protect the newly-poisoned commit once the active task completes.
8. When the active `Task` finishes, `trigger_continuous_delivery` (`stack.rb:210-229`) calls `next_commit_to_deploy`, which now can select/deploy the attacker-influenced commit for a repository the attacker does not own.

`verify_signature`, `require_permission!`, `ExplicitParameters` schema (`StatusHandler.params` only validates types, not ownership), and model validations do not close this gap — none of them check that the `sha` being updated belongs to the stack identified by the payload's `repository`.

### Impact Explanation
An attacker who owns/administers any tenant org onboarded on the same Shipit instance can write arbitrary `Status` rows (state, context, description, target_url) onto commits belonging to a **different tenant's** stack, as long as that commit's sha is reproducible/shared. This can alter `deployable?`, `blocked?`, and consequently which commit `trigger_continuous_delivery` deploys for a stack the attacker does not control — an unauthorized deploy decision on another organization's stack. This is a cross-tenant write (one repository's webhook mutating another repository's `Commit`/`Task` queue), matching the Critical category "a payload for one repository mutating another's stack, commit, task or team" / "an unauthorized deploy". Blast radius is bounded by shared `sha` values across stacks, but is fully repeatable per shared commit and requires no privilege beyond ordinary tenant access to one's own onboarded org/webhook.

### Likelihood Explanation
Preconditions: Shipit instance must host (or the attacker must be able to onboard) more than one organization/stack, and there must exist a `Commit` row with an identical `sha` in both the attacker's stack and the victim's stack — this is the normal case for forks, mirrors, or shared-history repos, which are common. The attacker needs only ordinary access to their own tenant's genuine webhook signing (no Shipit secrets, no victim credentials). No GitHub hash collision is required — SHA-1 of a git commit object is fully reproducible from public repo content. This is a low-cost, repeatable attack against any stack sharing commit history with an attacker-controlled repo.

### Recommendation
Scope `StatusHandler#process` (and the equivalent check-run handler) to only update commits whose `stack.repository.full_name` (or `github_repo_name`) matches the webhook payload's `repository.full_name`, e.g.:
```ruby
Commit.joins(:stack).where(sha: params.sha, stacks: { ... repository matching payload.repository.full_name ... }).each { |c| c.create_status_from_github!(params) }
```

### Proof of Concept
```ruby
# test/models/webhooks/status_handler_cross_repo_test.rb
test "status webhook from one repository does not affect a commit belonging to another stack with the same sha" do
  victim_stack = shipit_stacks(:shipit)          # continuous_deployment: true, active task fixture
  attacker_stack = shipit_stacks(:cyclimse)       # different repository/org

  shared_sha = "deadbeef" * 5
  victim_commit = victim_stack.commits.create!(sha: shared_sha, message: "shared", author: shipit_users(:walrus), committer: shipit_users(:walrus), authored_at: Time.now, committed_at: Time.now)
  attacker_stack.commits.create!(sha: shared_sha, message: "shared", author: shipit_users(:walrus), committer: shipit_users(:walrus), authored_at: Time.now, committed_at: Time.now)

  before = victim_stack.next_expected_commit_to_deploy

  # Genuinely signed webhook for attacker's own org/repo, targeting the shared sha
  Shipit::Webhooks::Handlers::StatusHandler.new.call(
    "sha" => shared_sha, "state" => "success", "context" => "ci/attacker",
    "repository" => { "full_name" => attacker_stack.repository.full_name, "owner" => { "login" => attacker_stack.repository.owner } }
  )

  victim_commit.reload
  after = victim_stack.next_expected_commit_to_deploy

  assert victim_commit.statuses.where(context: "ci/attacker").exists?, "attacker-authored status was written onto the victim's commit"
  refute_equal before, after, "next_expected_commit_to_deploy for the victim stack changed due to a foreign-repo webhook"
end
```