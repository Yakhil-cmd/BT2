### Title
`StatusHandler#process` writes a `Status` to any stack's commit matched by SHA alone, with zero repository/organization binding to the webhook that authenticated the request - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` looks up commits with `Commit.where(sha: params.sha)` across the entire `commits` table, and never uses `Handler#stacks` or `Handler#repository_name` to scope the query to the repository that the webhook's signature verified. Any org owning a valid `webhook_secret` can trigger `commit.create_status_from_github!` (and thus `Status.create`) on a commit belonging to an unrelated stack/org, as long as they know its SHA.

### Finding Description
The claimed binding is: **org verified by `verify_signature` == org that owns the `Stack`/`Commit` a `Status` is written to**.

`WebhooksController#verify_signature` resolves the signing org purely from `repository.owner.login` in the attacker-controlled JSON body: [1](#0-0) [2](#0-1) 

This only proves "the sender knows the webhook secret for `repository.owner.login`" - it says nothing about which stack/commit the payload should affect.

`StatusHandler#process` is supposed to use that same payload's repository context to scope the write, via `Handler#stacks`/`#repository_name`: [3](#0-2) 

But it does not call `stacks` or `repository_name` at all: [4](#0-3) 

It queries `Commit.where(sha: params.sha)` globally - across every stack of every repository/org in the Shipit instance - and calls `commit.create_status_from_github!(params)` for each match, which creates a `Status` row (`Shipit::Status`), immediately fires `enable_ci_on_stack`, `schedule_continuous_delivery`, and `stack.schedule_merges`: [5](#0-4) [6](#0-5) [7](#0-6) 

**Exploit flow:** the attacker (owner of `attacker-org`, holding `attacker-org`'s valid `webhook_secret`) sends `POST /webhooks` with header `X-Github-Event: status` and body `{"repository":{"owner":{"login":"attacker-org"},"full_name":"attacker-org/whatever"},"sha":"<victim commit sha>","state":"success", ...}`. `verify_signature` succeeds because it only checks the signature against `attacker-org`'s secret, matching `repository.owner.login`. `StatusHandler#process` then runs `Commit.where(sha: ...)`, which matches the victim's commit regardless of the `repository.full_name`/owner claimed in the payload, and writes a `success` `Status` on it. This is even broader than the question's premise: the handler doesn't need a spoofed `repository.full_name` scoping bug — it performs **no repository scoping whatsoever**, so any org's webhook secret can forge a status on any commit in the database as long as the SHA is known (commit SHAs of public repos are trivially discoverable).

None of the listed guards prevent this: `verify_signature` only authenticates the claimed owner org, not a relationship to the target stack; `ExplicitParameters` only validates payload shape (`sha`, `state`, etc.), not repository binding; `drop_unhandled_event` and `force_github_authentication`/`User#authorized?` are irrelevant to unauthenticated webhook ingestion; the `stacks`/`repository_name` scoping helper exists in the base `Handler` class but `StatusHandler` simply never calls it.

### Impact Explanation
A `Status` row is written for a repository/stack that the sending organization never authenticated for. Since `Status#after_create :enable_ci_on_stack` and `schedule_continuous_delivery` fire, and `commit.create_status_from_github!` triggers `stack.schedule_merges` on `pending`/`success` states, this can flip a victim commit's CI/deployable state and unblock `MergeRequest#any_status_checks_missing?`/`#any_status_checks_failed?` gating (via `StatusChecker` in `app/models/shipit/merge_request.rb`) and continuous-deployment triggers. This is a cross-tenant forged CI status / authentication-bypass class issue — attacker-controlled data written into another org's stack via a "verified" but unrelated webhook signature — matching the Critical category ("a payload for one repository mutating another's stack, commit, task or team," or "unauthorized deploy/merge"). It is fully repeatable against arbitrary stacks/commits as long as the attacker knows a target SHA.

### Likelihood Explanation
Preconditions are low-cost for the attacker: own any GitHub org integrated with the same Shipit instance (or any org configured in `Shipit.github` with a valid `webhook_secret`), know a target commit SHA in the victim's stack (public for public repos, or leaked via any status/PR notification), and send one crafted HTTP POST to `/webhooks`. No Shipit session, API token, or GitHub write access to the victim repo is required.

### Recommendation
Scope `StatusHandler#process` to the repository resolved by `Handler#stacks`/`#repository_name` (the same payload field used by `verify_signature` to pick the org), e.g. `stacks.joins(:commits).merge(Commit.where(sha: params.sha))` or `stacks.each { |stack| stack.commits.find_by(sha: params.sha)&.create_status_from_github!(params) }`, instead of the unscoped `Commit.where(sha: params.sha)`.

### Proof of Concept
Minitest under `test/models/shipit/webhooks/handlers/status_handler_test.rb` (or `test/controllers/webhooks_controller_test.rb`):
1. Create `victim_stack` for repo `victim-org/victim-repo` with a commit `victim_commit` (known `sha`).
2. Create `attacker` org config with its own `webhook_secret`, unrelated to `victim-org`.
3. Sign a `status` payload with `attacker-org`'s secret: `{"repository": {"owner": {"login": "attacker-org"}, "full_name": "attacker-org/some-repo"}, "sha": victim_commit.sha, "state": "success"}`.
4. POST to `/webhooks` with header `X-Github-Event: status` and correct `X-Hub-Signature` for the attacker's secret.
5. Assert: `assert_response :ok`; `assert_difference('victim_commit.statuses.count', 1) { ... }`; `assert_equal 'success', victim_commit.reload.state`; assert that `MergeRequest::StatusChecker.new(victim_commit, victim_commit.statuses_and_check_runs, victim_stack.cached_deploy_spec).success?` becomes true — demonstrating the equality "verifying org == owning org" is violated (`attacker-org` vs `victim-org`) yet the write succeeds.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** app/models/shipit/status.rb (L18-19)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create
```
