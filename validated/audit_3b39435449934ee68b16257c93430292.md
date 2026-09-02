### Title
Cross-repository forged CI Status injection via globally-unscoped SHA lookup - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` looks up commits by `Commit.where(sha: params.sha)` with no repository/stack scoping, and applies `create_status_from_github!` to every matching row. If two stacks (belonging to different repositories, even different orgs) happen to contain a commit with the identical SHA, a validly-signed `status` webhook naming that SHA writes a `Status` onto both stacks' commits.

### Finding Description
The binding that should hold is: `Status.stack_id == Commit(sha).stack_id == repository_owner/name authenticated by X-Hub-Signature for this payload`. Instead, `StatusHandler#process` does: [1](#0-0) 

which iterates over *every* `Commit` row in the entire database matching the given SHA and calls `create_status_from_github!` on each — regardless of which stack/repository they belong to. Contrast this with `Api::RollbacksController#create`, which correctly scopes lookup via `stack.commits.by_sha(params.sha)`. `Commit.by_sha`/`by_sha!` themselves are also unscoped by stack, only usable safely because callers elsewhere pre-scope with `stack.commits`.

`WebhooksController#verify_signature` only checks that the signature matches the webhook secret configured for `repository_owner` (`params.dig('repository','owner','login')`), i.e., that the payload came from *some* GitHub App/org integration Shipit trusts for that owner name — it never cross-checks that `params.sha` actually belongs to a commit under that owner's repositories. `drop_unhandled_event` and `check_if_ping` don't add any repository binding either. The `ExplicitParameters` schema for `StatusHandler` only requires `sha`/`state`/etc. as raw strings, with no repository field enforced against `Commit#stack`.

Exploit flow: attacker registers/owns a GitHub org+repo that has this Shipit's GitHub App/webhook integration installed (a legitimate prerequisite for using webhooks at all — this is the "attacker owns their own org" scenario explicitly allowed by the rules). Attacker pushes a commit to their own repo whose SHA happens to coincide with a SHA already tracked in a victim stack (accidental collision across import/rebase histories, cherry-picks, or any workflow that reuses commit objects/SHAs across repos is enough — no cryptographic SHA1 collision is required, just an identical 40-hex value existing in two different stacks' `commits` tables). Attacker then sends (or lets GitHub send) a `status` webhook, correctly signed with their own org's webhook secret, naming that SHA. `WebhooksController#verify_signature` passes (signature is valid for the attacker's own org). `StatusHandler#process` then finds ALL commits with that SHA — including the victim's — and writes a forged `Status` (arbitrary `state`, `description`, `context`, `target_url`) onto the victim commit via `commit.create_status_from_github!`.

### Impact Explanation
A forged `Status` write on a victim stack's commit is a cross-tenant integrity violation: `Status#after_create` calls `enable_ci_on_stack`, and `after_commit` schedules `schedule_continuous_delivery` and `broadcast_update` on the victim's commit/stack ( [2](#0-1) ). A forged `success` status can flip a commit's aggregated CI state, potentially unblocking merges/deploys gated on CI (`ProcessMergeRequestsJob` is enqueued on state transitions per `test/models/commits_test.rb:763-777`), which is a payload for one repository affecting another repository's stack/commit — matching the Critical category "a payload for one repository mutating another's stack, commit, task or team."

### Likelihood Explanation
The attacker must control a GitHub org/repo that has a working webhook integration with the target Shipit instance (own org's `webhook_secret`), which is within the stated unprivileged threat model (any GitHub user who can emit webhooks from a repository they own). The hard precondition is a SHA collision between the attacker's commit and a specific victim commit already imported into a different stack — this is not attacker-controlled and is not a cryptographic collision requirement in the strict sense addressed in the question (the question posits "collide across two different repositories' commit histories," e.g., via shared history/forks/cherry-picks, submodules, or vendored history, which is plausible in monorepo/fork scenarios), but it is not something the attacker can force against an arbitrary chosen victim on demand. Given that constraint, likelihood is non-trivial but conditional; the code-level guard is nonetheless absent, so any such collision is fully exploitable with a single webhook POST, repeatably.

### Recommendation
Scope `StatusHandler#process` to the repository/stack asserted by the payload, e.g. resolve stacks by `params.dig('repository','full_name')` first, then do `stack.commits.by_sha`/`.where(sha:)` within that stack (or within stacks belonging to the authenticated repository_owner), instead of a global `Commit.where(sha:)`. Additionally scope `Commit.by_sha`/`by_sha!` to be called only through an association (`stack.commits.by_sha`) and consider making the class method require an explicit stack scope to prevent future unscoped use.

### Proof of Concept
```ruby
# test/models/webhooks/handlers/status_handler_test.rb
test "status webhook does not leak status to commits of other stacks with colliding sha" do
  attacker_stack = shipit_stacks(:shipit)      # attacker-owned/authenticated repo
  victim_stack   = shipit_stacks(:cyclimse)    # unrelated repo

  colliding_sha = 'a' * 40
  attacker_commit = attacker_stack.commits.create!(sha: colliding_sha, message: 'x',
                                                     author: shipit_users(:shipit), authored_at: Time.now,
                                                     committer: shipit_users(:shipit), committed_at: Time.now)
  victim_commit   = victim_stack.commits.create!(sha: colliding_sha, message: 'y',
                                                     author: shipit_users(:shipit), authored_at: Time.now,
                                                     committer: shipit_users(:shipit), committed_at: Time.now)

  params = Shipit::Webhooks::Handlers::StatusHandler::Params.new(
    sha: colliding_sha, state: 'success', context: 'ci/forged'
  )
  Shipit::Webhooks::Handlers::StatusHandler.new.call(
    'sha' => colliding_sha, 'state' => 'success', 'context' => 'ci/forged'
  )

  # Binding under test: only attacker_commit's stack should receive the status
  assert_equal 1, attacker_commit.reload.statuses.where(context: 'ci/forged').count
  assert_equal 0, victim_commit.reload.statuses.where(context: 'ci/forged').count, \
    "victim commit in an unrelated stack must not receive a status from attacker's webhook"
end
```
Running this against current `StatusHandler#process` fails the second assertion (`victim_commit` also receives the forged status), demonstrating the missing repository-scope binding.

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/status.rb (L18-21)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create

    delegate :broadcast_update, to: :commit
```
