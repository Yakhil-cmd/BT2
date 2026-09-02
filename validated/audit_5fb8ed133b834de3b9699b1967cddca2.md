### Title
`StatusHandler#process` mutates Commit rows across all repositories/stacks without validating or scoping by `repository` - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler`'s `ExplicitParameters` schema never declares `repository` as required or even accepted, and `process` queries `Commit.where(sha: params.sha)` globally instead of scoping through the `stacks`/`repository_name` helper that every other handler (`PullRequest::OpenedHandler`, `ClosedHandler`, `LabeledHandler`, etc.) uses. Any correctly-signed status webhook for org A therefore updates every `Commit` row in the database sharing that SHA, including commits that belong to stacks owned by a completely unrelated org B.

### Finding Description
The claimed binding is: `payload['repository']['full_name'] == <verified sender org>` AND that same value `== <repository of the stack/commit mutated>`.

Tracing the code:
- `WebhooksController#verify_signature` derives `repository_owner` from `params.dig('repository','owner','login')` (or `organization.login`) and calls `Shipit.github(organization: repository_owner).verify_webhook_signature(...)` [1](#0-0) . This only proves the request was signed with **some** org's `webhook_secret` — it does not bind that org to anything checked later inside the handler.
- `Handler#initialize` parses `payload` through `self.class.param_parser.parse!(payload)` [2](#0-1) .
- `StatusHandler`'s schema requires only `sha` and `state`; it never declares `requires :repository` [3](#0-2) . Compare to `PullRequest::OpenedHandler`/`ClosedHandler`/`LabeledHandler`, which all `requires :repository do requires :full_name, String end` [4](#0-3) .
- `StatusHandler#process` never calls the base class's `stacks`/`repository_name` scoping helpers [5](#0-4) ; instead it does:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [6](#0-5) 
This is a global, unscoped lookup across **all** stacks/repositories in the Shipit instance. `commit.create_status_from_github!` then writes a `Status` row tied to `commit.stack_id` [7](#0-6) , i.e. it mutates whatever stack that commit belongs to — irrespective of which org's `webhook_secret` verified the request.

Root cause: repository binding is checked only for *authentication* (which org's secret signed the message), never for *authorization scope* (which repository's commits may be mutated). Since git SHA-1 is content/history-addressed, forks and repos sharing common ancestor commits routinely contain identical commit SHAs. An attacker who owns/administers a repository that is itself onboarded as a Shipit-monitored org (a legitimate, low-privilege multi-tenant scenario — no victim secrets needed) can send a validly-signed status webhook for their own repo whose `sha` matches a commit that also exists (from shared git history, e.g., a forked base commit) in a victim org's stack. `StatusHandler` will then create/replace a status on the victim's commit, since it never checks `payload['repository']['full_name']` against the commit's `stack.repository`.

The requested PoC scenario — omitting `repository` entirely — succeeds trivially because `repository` was never required by the schema, and `process` never reads it at all; the missing key changes nothing about which commits get mutated.

Existing guards (`verify_signature`, `drop_unhandled_event`, `ExplicitParameters`) all fail to prevent this because they operate one layer above: they confirm *a* legitimate org sent *some* signed payload, but `StatusHandler` performs its DB write with no reference to that org or to `payload['repository']` at all.

### Impact Explanation
An attacker with a legitimate but unrelated Shipit-onboarded org can cause `Commit#create_status_from_github!` to execute for a commit belonging to a different org's stack, writing an attacker-controlled `state`/`description`/`target_url` status. Since `Status` affects `Commit#deployable?`/`blocked?` and can trigger `stack.schedule_merges` (continuous delivery scheduling) via `add_status` [8](#0-7) , this is a payload from one repository mutating another repository's stack/commit state — matching the Critical category ("a payload for one repository mutating another's stack, commit, task or team"). It is repeatable against any commit SHA shared across tenant boundaries (common for forks/mirrors of the same upstream history).

### Likelihood Explanation
Requires the attacker to control (or have webhook access to) at least one org/repo that is itself configured in Shipit with its own `webhook_secret` — i.e., the attacker must be a legitimate low-privilege tenant of the same multi-tenant Shipit instance, not an arbitrary internet user with zero relationship to Shipit. Given that precondition, exploitation cost is low: send a normal `status` event for a commit SHA known to also exist in another tenant's history (trivial for forks/mirrors of the same open-source project). No secrets belonging to the victim org are needed.

### Recommendation
In `StatusHandler`, require `repository.full_name` in the params schema (matching the other handlers) and scope the `Commit` lookup through `Repository.from_github_repo_name(params.repository.full_name).stacks` (or the existing `stacks` helper in `Handler`) instead of a bare `Commit.where(sha: params.sha)`, so only commits belonging to the verified repository's own stacks can be mutated.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
test "StatusHandler mutates commits of unrelated stacks and does not require `repository`" do
  victim_stack = shipit_stacks(:shipit)  # some other org's stack
  attacker_owned_sha = victim_stack.commits.first.sha  # shared SHA from history collision/fork

  params = {
    'sha' => attacker_owned_sha,
    'state' => 'success'
    # note: no 'repository' key at all
  }

  assert_difference -> { victim_stack.commits.find_by(sha: attacker_owned_sha).statuses.count }, 1 do
    Shipit::Webhooks::Handlers::StatusHandler.call(params)
  end
end
```
This asserts that `commit.create_status_from_github!` runs and mutates `victim_stack`'s commit even though `payload['repository']` is absent, proving `full_name` is neither required nor checked against the commit's actual owning stack.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L21-24)
```ruby
        def initialize(payload)
          @payload = payload
          @params = self.class.param_parser.parse!(payload)
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L7-18)
```ruby
        params do
          requires :sha, String
          requires :state, String
          accepts :description, String
          accepts :target_url, String
          accepts :context, String
          accepts :created_at, String

          accepts :branches, Array do
            requires :name, String
          end
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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L33-35)
```ruby
            requires :repository do
              requires :full_name, String
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

**File:** app/models/shipit/commit.rb (L366-384)
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
```
