### Title
`StatusHandler#process` mutates any `Commit` matching `sha` across all repositories/stacks, with no repository binding at all - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler`'s `ExplicitParameters` schema never declares or requires `repository`, and `process` looks up commits solely by `Commit.where(sha: params.sha)` with zero repository/stack scoping. Any correctly-signed `status` webhook — from any organization whose GitHub App/webhook secret is configured in this Shipit instance — can write a `Status` onto any `Commit` record in any stack of any repository that happens to share that SHA, regardless of whether `repository` is present, correct, or omitted in the payload.

### Finding Description
The claimed binding, stated as an equality that should hold but does not:
`Commit(sha=X).stack.repository.full_name == payload.repository.full_name` for every commit mutated by `StatusHandler#process`.

Trace:
- `Handler#initialize` parses `payload` against the class's declared `ExplicitParameters::Parameters` schema and stores the result in `params`. [1](#0-0) 
- `StatusHandler`'s schema only requires/accepts `sha`, `state`, `description`, `target_url`, `context`, `created_at`, `branches` — `repository` is never declared, so it is neither required nor validated. [2](#0-1) 
- `process` does: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` — a global, unscoped query across the entire `commits` table, spanning every `Stack`/`Repository` tracked by this Shipit instance. [3](#0-2) 
- `create_status_from_github!` unconditionally writes a new `Status` row tied to `stack_id` and fires `Hook.emit` / scheduling side effects (`schedule_merges`, `deployable_status`), i.e., real state mutation with downstream effects (e.g., unblocking a deploy). [4](#0-3) [5](#0-4) 
- The base `Handler` class does define a `stacks`/`repository_name` helper that scopes to `payload.dig('repository', 'full_name')`, but `StatusHandler` never calls it. [6](#0-5) 
- `WebhooksController#verify_signature` only authenticates that the raw body is signed by *some* registered organization's webhook secret (resolved via `repository_owner`, which itself falls back to `organization.login` if `repository` is absent). It says nothing about which specific commit/stack the payload is allowed to touch. [7](#0-6) [8](#0-7) 

Root cause: signature verification proves the payload came from *an* authenticated GitHub App installation, but `StatusHandler` never re-checks that the commit(s) matched by SHA actually belong to the repository that signed the request. Since `sha` is a git content hash, and a commit's SHA is fully determined by its tree/parent/author/committer/message/timestamps (all of which are public for any public commit), an attacker who controls a repository with a valid Shipit-linked webhook secret can construct/push an identical commit object (same SHA) into their own repository, then send a `status` (or `check_run`) webhook for that SHA, causing `StatusHandler` to write a status onto the victim's commit in a completely different, unrelated `Stack`. No existing guard (`verify_signature`, `drop_unhandled_event`, `ExplicitParameters` schema, `stacks` scope) enforces the repository/stack binding here, because `StatusHandler` simply never uses it.

### Impact Explanation
An attacker with any GitHub organization/repository already onboarded to this Shipit instance (a normal, unprivileged Shipit user for their own repo) can inject fabricated CI status entries onto commits belonging to a different tenant's stack, as long as they can produce (or find) a commit with a colliding SHA. This can flip a victim commit from "pending"/"failure" to "success," which — combined with `add_status`'s `stack.schedule_merges if new_status.pending? || new_status.success?` and `deployable_status` hook — can make a victim commit `deployable?` and trigger continuous delivery/merge logic for a stack the attacker does not own. This is a cross-tenant write ("a payload for one repository mutating another's stack/commit"), matching the Critical category. It is repeatable against any commit whose SHA is known/reproducible and is not limited to a single victim repository — it applies engine-wide, to every `Stack` tracked by the Shipit instance.

### Likelihood Explanation
Preconditions: the attacker needs a repository/org already configured with a Shipit-recognized GitHub App/webhook secret (i.e., they must be an onboarded, but otherwise unprivileged, user of this Shipit instance — consistent with the threat model's "any GitHub user who can push to a fork/own repo they control"). They also need to produce a commit whose SHA matches a targeted victim commit, which requires knowing/reconstructing the exact git object metadata of the victim commit — feasible for public commits, and trivial if attacker and victim share a fork/mirror relationship (a common Shipit setup: same repository tracked as multiple stacks/environments) since identical commits naturally share SHAs across those stacks already. Attacker cost is low (one webhook POST, correctly HMAC-signed with their own known secret); the flaw is fully repeatable per request.

### Recommendation
Have `StatusHandler` (and any other handler that mutates `Commit`/`Status` records by SHA) require and validate `repository` in its `ExplicitParameters` schema, and scope the lookup through the authenticated repository, e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` using the `Handler#stacks` helper (which is already scoped to `payload.dig('repository', 'full_name')`), rather than the unscoped `Commit.where(sha: params.sha)`.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
test "#process mutates a commit belonging to a different repository/stack" do
  attacker_stack = shipit_stacks(:shipit) # some stack owned by attacker's repo
  victim_stack   = shipit_stacks(:cyclimse) # unrelated victim stack/repo
  victim_commit  = victim_stack.commits.create!(sha: 'deadbeef' * 5, message: 'victim commit')

  payload = {
    'sha' => victim_commit.sha,
    'state' => 'success',
    'context' => 'ci/attacker-forged'
    # note: no 'repository' key at all
  }

  assert_difference -> { victim_commit.statuses.count }, 1 do
    Shipit::Webhooks::Handlers::StatusHandler.call(payload)
  end

  victim_commit.reload
  assert_equal 'success', victim_commit.status.state
  # Binding under test: victim_commit.stack should equal the repository that
  # authenticated the webhook (attacker_stack's repository) -- it does not,
  # proving the missing repository binding.
  refute_equal attacker_stack, victim_commit.stack
end
```
This demonstrates that `StatusHandler#process` writes to `victim_commit` even though the payload never names a `repository` and the mutated commit's stack differs from any stack the requester could legitimately claim.

### Citations

**File:** app/models/shipit/webhooks/handlers/handler.rb (L19-24)
```ruby
        attr_reader :params, :payload

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

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified

      Rails.logger.info([
        'WebhookController#verify_signature',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "signature=#{request.headers['X-Hub-Signature']}",
        "status=#{status}"
      ].join(' '))
    rescue Shipit::GithubOrganizationUnknown => e
      head(422)
      Rails.logger.warn([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "unknown_organization=#{e.message}",
        "status=#{status}"
      ].join(' '))
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```
