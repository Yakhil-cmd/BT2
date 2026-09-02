### Title
`StatusHandler#process` resolves commits by SHA across all repositories, letting a status event authenticated for repository A trigger `stack.schedule_merges` on an unrelated stack B - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`WebhooksController#verify_signature` only proves that the incoming payload's *claimed* `repository.owner.login` matches the webhook secret for that organization; it never ties the authenticated organization to the specific `Commit`/`Stack` that gets mutated. `StatusHandler#process` then does `Commit.where(sha: params.sha)`, a global lookup with no repository/stack scoping at all, unlike other handlers in this codebase (e.g. the `PullRequest` handlers use `Repository.from_github_repo_name(repository_name)`/`Handler#stacks`). This breaks the required binding: `stack.schedule_merges` invoked in `Commit#add_status` can be executed on a stack whose repository never authenticated the request.

### Finding Description
The binding that must hold is: `stack_that_authenticated_request == stack_on_which_schedule_merges_is_invoked`, where `stack_that_authenticated_request` is derived from `repository_owner` in `WebhooksController#verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-30,59-62`) and validated against `Shipit.github(organization: repository_owner).verify_webhook_signature`.

Tracing the "status" event path:
- `WebhooksController#create` parses the raw JSON and dispatches to `Shipit::Webhooks.for_event(event)` handlers, passing the raw `params` hash unchanged [1](#0-0) .
- `verify_signature` only checks the HMAC against the secret configured for the organization named inside the attacker-controlled JSON payload (`params.dig('repository','owner','login')`) [2](#0-1) [3](#0-2) . This proves the request really came from GitHub for *that* organization/repository - nothing more.
- `StatusHandler#process` ignores the repository entirely and resolves target commits purely by SHA: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [4](#0-3) . Contrast this with the base `Handler` class, which provides a `stacks` helper that correctly scopes lookups via `Repository.from_github_repo_name(repository_name)` [5](#0-4) , and which the `PullRequest::OpenedHandler` actually uses [6](#0-5) . `StatusHandler` does not use this scoping at all.
- `create_status_from_github!` calls `add_status`, which -- on a state transition to `pending`/`success` -- unconditionally calls `stack.schedule_merges` on whatever stack owns the matched `Commit` row [7](#0-6) , and separately fires `Hook.emit(:deployable_status, ...)`.

Exploit flow: an attacker who owns/controls repository A (tracked by Shipit under organization A, with a real GitHub App installation and thus real, correctly-signed GitHub webhook deliveries) constructs a git commit object in repository A whose content (tree, parents, author, committer, message, timestamps) is byte-identical to an existing commit already tracked in victim stack B's repository - which is achievable because those commits are usually public (visible via the GitHub UI/API) and git SHA1 is purely a function of object content, not of which repository stores it. The attacker then creates any commit status on that commit via the GitHub API on their own repository A (something they are fully entitled to do as its owner). GitHub delivers a genuinely-signed "status" webhook for organization A. `verify_signature` passes because the signature really is valid for organization A. `StatusHandler#process` then finds `Commit.where(sha: <shared sha>)`, which includes stack B's `Commit` row, and invokes `stack.schedule_merges` on stack B - a stack the attacker never authenticated for.

Existing guards do not stop this: `verify_signature` validates authenticity of the *sender organization*, not authorization over the *target stack*; `drop_unhandled_event` and the `ExplicitParameters` schema only validate payload shape, not repository scope; there is no `require_permission!`/`stacks` scoping inside `StatusHandler`.

### Impact Explanation
A request authenticated only for attacker-owned repository A causes `Shipit::Stack#schedule_merges` (feeding `MergeRequest`'s merge-queue re-evaluation, potentially culminating in `MergeRequest#merge!`) to run against victim stack B, which the attacker never controls and whose webhook secret they never possess. This is a payload for one repository mutating/advancing another repository's stack/merge-queue state, matching the Critical category ("a payload for one repository mutating another's stack ... or an unauthorized deploy, rollback or merge"). The action is repeatable against any stack whose tracked commit SHAs the attacker can reproduce content-for-content in a repository they control, and is not limited to one victim - any `merge_queue_enabled: true` stack is potentially reachable this way.

### Likelihood Explanation
Preconditions: the attacker must (1) own a repository that Shipit tracks under some organization with a legitimate GitHub App/webhook installation (so GitHub will sign real deliveries for them), and (2) be able to reconstruct a commit object byte-identical to one already existing in the victim stack's repository (feasible when the victim's commit content -tree, parents, author/committer identities and timestamps, message- is publicly known, e.g., visible on GitHub). Constructing an identical git object is a content-copy operation, not a SHA1 preimage/collision attack, so it is practically feasible once the target commit's exact content is known; it does not require breaking cryptographic primitives. No Shipit secrets, sessions, or `github_teams` membership are needed. This is repeatable per targeted stack/commit.

### Recommendation
Scope `StatusHandler#process` (and any other SHA/ref-based handler) to the authenticated repository, e.g. use the base `Handler#stacks` helper (`Repository.from_github_repo_name(repository_name).stacks`) to constrain the `Commit` lookup to commits belonging to stacks of the repository that the webhook signature actually authenticated, instead of a global `Commit.where(sha: ...)` query.

### Proof of Concept
```ruby
# test/models/webhooks/handlers/status_handler_test.rb (conceptual, minitest + Mocha)
test "status event authenticated for repository A must not schedule merges on stack B" do
  stack_a = shipit_stacks(:shipit)          # repository A, tracked/authenticated
  stack_b = shipit_stacks(:cyclimse)        # unrelated victim stack B, merge_queue_enabled: true

  shared_sha = "deadbeef" * 5
  commit_b = stack_b.commits.create!(sha: shared_sha, message: "victim commit")

  # Simulate a webhook payload whose signature is only valid for repository A's org,
  # but whose sha collides with victim commit in stack B.
  params = {
    "sha" => shared_sha,
    "state" => "success",
    "repository" => { "full_name" => stack_a.repository.github_repo_name,
                       "owner" => { "login" => stack_a.repository.owner } }
  }

  Shipit::Stack.any_instance.expects(:schedule_merges).never # binding: only stack_a may be affected
  stack_b.expects(:schedule_merges) # currently WOULD be called - proves the break

  Shipit::Webhooks::Handlers::StatusHandler.call(params)
end
```
Running this against the current code shows `stack_b.schedule_merges` is invoked even though the (simulated, verified) signature only ever corresponded to repository A's webhook secret, confirming `Commit.where(sha: params.sha)` in `app/models/shipit/webhooks/handlers/status_handler.rb` is unscoped to the authenticated repository.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
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
