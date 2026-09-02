### Title
Cross-repository commit status write via unscoped `Commit.where(sha:)` in `StatusHandler#process` - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`Shipit::Webhooks::Handlers::StatusHandler#process` looks up commits solely by `sha`, with no constraint on the stack/repository that authenticated the webhook. Because commit SHAs are shared verbatim between the origin repo and any fork/import that has the same commit in its history, an attacker who controls a repository sharing history with a victim's repository can send a signed status webhook for their own repository and have it applied to the victim's `Commit` record as well.

### Finding Description
The broken binding, stated as an equality that must hold but does not:
`verified_repository_owner(payload.repository.owner) == commit.stack.repository.owner` for every `Commit` mutated by the request.

Trace:
- `WebhooksController#verify_signature` resolves `Shipit.github(organization: repository_owner)` from `params.dig('repository','owner','login')` and validates the HMAC signature against that organization's `webhook_secret` only [1](#0-0) [2](#0-1) . This proves the payload came from attacker-org's app configuration — it says nothing about which `Commit`/`Stack` rows may be touched.
- `WebhooksController#create` then dispatches the parsed body to every handler for the event with no re-derivation or scoping by the verified repository [3](#0-2) .
- `StatusHandler#process` runs `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` — this query has no `stack_id`/repository filter at all [4](#0-3) .
- `Commit#create_status_from_github!` calls `add_status`, which writes a `Status` row, emits `commit_status`/`deployable_status` hooks, and — critically — calls `stack.schedule_merges if new_status.pending? || new_status.success?` [5](#0-4) [6](#0-5) .

Exploit flow: attacker owns `attacker-org` and configures its own Shipit `webhook_secret` (a normal, unprivileged setup step for any org that installs the GitHub App). Attacker's repo shares a commit (same 40-hex SHA) with `victim-org/victim-repo` — plausible via forks, cherry-picks, subtree merges, or repo migrations, which Shipit itself supports (stacks can be pointed at renamed/migrated repositories, and a `Commit` row persists across such changes since it's only keyed by `sha` and `stack_id`, not validated against the live GitHub repo identity at write time). Attacker POSTs `/webhooks` with a `status` event for `attacker-org/attacker-repo`, `sha` = the shared SHA, `state: "success"`, signed with attacker's own valid `webhook_secret`. `verify_signature` passes (correctly, for attacker-org). `StatusHandler#process` then finds and mutates **every** `Commit` row across **all** stacks/orgs with that SHA, including the victim's, writing an attacker-controlled status and potentially triggering `stack.schedule_merges` for the victim's stack.

None of the listed guards prevent this: `verify_signature` only proves provenance of the app/org, not of the specific commit/stack being written; `drop_unhandled_event` and the `ExplicitParameters` schema only validate the shape of `sha`/`state`, not repository scoping; there is no `stacks` scope or repository-equality check anywhere in `StatusHandler`.

### Impact Explanation
Executes: an unauthenticated write of `Shipit::Status` on a commit belonging to a repository/stack the attacker does not control, and can flip a victim stack's commit into a "success" state, invoking `stack.schedule_merges` — a path toward an unauthorized deploy/merge on `victim-org/victim-repo`. This is a payload for one repository mutating another's commit/stack, matching the Critical severity category explicitly listed in the rules. Blast radius is cross-tenant: any Shipit instance hosting multiple orgs' stacks where two repositories share commit history is affected, and the attack is repeatable per shared SHA/event.

### Likelihood Explanation
Preconditions: attacker needs a Shipit-registered stack/app config for a repository they own (ordinary, unprivileged onboarding), and a shared-history commit with the victim's repo (realistic for forks, imported repos, or repos that were migrated/renamed within Shipit while retaining old `Commit` rows). No Shipit or GitHub secrets belonging to the victim are required; the attacker only ever uses their own valid `webhook_secret`. Cost is a single crafted HTTP POST, fully repeatable and scriptable.

### Recommendation
Scope the `Commit` lookup in `StatusHandler#process` (and any other handler using bare `sha`/`ref` lookups) to the stack(s) belonging to the repository verified in `WebhooksController#verify_signature` — e.g., join through `Stack` on `repository_owner`/`repository_name` derived from the payload, or pass the verified repository into the handler and filter `Commit.joins(:stack).where(sha: params.sha, shipit_stacks: { ... repository match ... })` before calling `create_status_from_github!`.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb (illustrative)
test "status webhook for attacker repo must not mutate victim repo's commit with same sha" do
  shared_sha = "a" * 40

  attacker_stack = shipit_stacks(:shipit) # stack backed by attacker-org/attacker-repo
  victim_stack   = create_stack(repository: create_repository(owner: "victim-org", name: "victim-repo"))

  attacker_commit = attacker_stack.commits.create!(sha: shared_sha, message: "shared")
  victim_commit   = victim_stack.commits.create!(sha: shared_sha, message: "shared")

  payload = {
    "sha" => shared_sha,
    "state" => "success",
    "repository" => { "owner" => { "login" => "attacker-org" }, "name" => "attacker-repo" }
  }

  Shipit::Webhooks::Handlers::StatusHandler.new.process # invoked via signed POST /webhooks as attacker-org

  assert_equal 1, attacker_commit.reload.statuses.count, "attacker's own commit should get the status"
  assert_equal 0, victim_commit.reload.statuses.count,
    "victim-org's commit must NOT receive a status from an attacker-org-signed payload"
end
```
This fails today because `Commit.where(sha: shared_sha)` matches both `attacker_commit` and `victim_commit`, so `victim_commit.statuses.count` becomes `1` instead of `0`.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-30)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/commit.rb (L366-386)
```ruby
    def add_status
      already_deployed = deployed?

      previous_status = status
      yield
      reload # to get the statuses into the right order (since sorted :desc)
      new_status = status

      unless already_deployed
        payload = { commit: self, stack:, status: new_status.state }
        Hook.emit(:commit_status, stack, payload.merge(commit_status: new_status)) if previous_status != new_status
      end

      if previous_status.simple_state != new_status.simple_state
        if !already_deployed && (!new_status.pending? || previous_status.unknown?)
          Hook.emit(:deployable_status, stack, payload.merge(deployable_status: new_status))
        end
        stack.schedule_merges if new_status.pending? || new_status.success?
      end
      new_status
    end
```
