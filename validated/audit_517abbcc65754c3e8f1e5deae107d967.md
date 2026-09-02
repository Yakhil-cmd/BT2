### Title
Cross-repository Status forgery via global `Commit.where(sha:)` lookup - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` writes GitHub `status` webhook data onto **every** `Commit` row that shares the payload's `sha`, without ever checking that the commit belongs to a stack tracking the payload's `repository`. Because `WebhooksController#verify_signature` only authenticates that the payload really came from GitHub for the org named in `payload['repository']['owner']['login']`, but never re-checks repository/stack ownership of the matched commit rows, a webhook that is 100% legitimately signed for repo A can silently mutate commit state that belongs to repo B/stack B whenever the two repositories happen to share a commit SHA (e.g. via a fork, mirror, or subtree relationship).

### Finding Description
The broken binding, as an equality that should hold but doesn't:
`commit.stack.repository.full_name == payload.dig('repository', 'full_name')`

Trace:
- `WebhooksController#verify_signature` computes `repository_owner = params.dig('repository', 'owner', 'login')` and calls `Shipit.github(organization: repository_owner).verify_webhook_signature(...)` [1](#0-0) [2](#0-1) . This only proves the request is a genuine GitHub webhook for that org's app installation - it says nothing about which specific commit rows may be touched.
- `Handler#initialize`/`.call` just parses params and dispatches to `#process`; the base class exposes `#stacks`/`#repository_name` helpers scoped by `Repository.from_github_repo_name(repository_name)` [3](#0-2) , but `StatusHandler` never calls them.
- `StatusHandler#process` does a completely unscoped, install-wide lookup: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [4](#0-3) .
- `Commit#create_status_from_github!` writes a `Status` row and, through `#add_status`, can emit `deployable_status`/`commit_status` hooks and unblock the commit for deploy via `deployable?` [5](#0-4) [6](#0-5) [7](#0-6) .

Root cause: git commit SHAs are content-addressed and repository-independent. Any two repositories that share history (a fork, a mirror, a subtree/vendor import, or simply the same upstream commit pulled into two orgs' Shipit-tracked repos) will contain rows in the shared `commits` table with identical `sha` but different `stack_id`. `StatusHandler` has no repository/stack filter, so a correctly-signed status webhook for repo A's commit X will also be applied to repo B's row for commit X if `Commit.where(sha: X)` returns both.

Attacker's exact request: the attacker owns/controls a repository (e.g. a public fork of the victim's upstream project) on which the Shipit GitHub App is installed (a normal, unprivileged action for any GitHub App that supports public installation, or for any org the attacker legitimately participates in). Because the fork shares commit history with the upstream repo tracked by a victim's Shipit stack, a specific commit SHA `X` exists identically in both. The attacker sets a commit status on their own commit `X` via the GitHub API (an action they are fully authorized to take on their own repo) causing GitHub to emit a real, correctly HMAC-signed `status` event to `POST /webhooks` with `repository.full_name = attacker/fork` and `sha = X`. `verify_signature` passes because the signature really is valid for the attacker's own org. `StatusHandler#process` then matches `Commit.where(sha: X)`, which includes the victim's row for `X` under a completely different stack, and writes a forged `Status` there, potentially flipping `deployable?` and unblocking that commit for deploy.

Existing guards do not stop this: `verify_signature`/`GitHubApp#verify_webhook_signature` authenticate the *sender* org, not the *target* commit's ownership; `drop_unhandled_event` only checks that a handler exists for the event type; the `ExplicitParameters` schema in `StatusHandler.params` only validates shape (`sha`, `state`, etc.), not repository scoping; and no model validation on `Commit`/`Status` enforces that the sha belongs to the reporting repository.

### Impact Explanation
A correctly-authenticated webhook for one repository/org can write a `Status` row (and trigger `deployable_status`/`commit_status` hooks) against a `Commit` belonging to a completely different stack/tenant, without that tenant's repository ever having authenticated the payload. This can flip `Commit#deployable?` for the victim's commit (via forged success/failure states feeding `blocked?`/`deployable?`), potentially enabling an unauthorized deploy of that commit, or conversely blocking a legitimate deploy by injecting a fake failing status. This matches the Critical category "a payload for one repository mutating another's stack, commit, task or team." The blast radius spans any two Shipit-tracked repositories that share commit history (forks, mirrors, subtree imports), which is common in real multi-tenant Shipit deployments, and the attack is repeatable per shared commit.

### Likelihood Explanation
Requires: (1) a multi-tenant Shipit install tracking more than one repository/stack, (2) at least one pair of tracked repositories sharing commit history (fork/mirror/subtree - a common real-world condition, not a hash collision requiring cryptographic preimage work), and (3) the attacker being able to get a genuinely-signed `status` event sent for their own repo (achievable via GitHub's own status API on a repo they control, provided the Shipit GitHub App/webhook is installed there - a normal unprivileged action for public/installable apps). No Shipit secret, session, or privileged role is needed; the attacker relies entirely on legitimate GitHub signing of their own webhook. This is realistically exploitable wherever forks/mirrors of tracked repos exist, and is repeatable for every shared commit SHA.

### Recommendation
Scope `StatusHandler#process` (and any other handler doing a bare `Commit.where(sha:)` lookup) to the commits belonging to the stacks resolved from the verified payload's repository, e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` or `Commit.where(sha: params.sha, stack_id: stacks.select(:id))`, using the existing `Handler#stacks`/`#repository_name` helpers, so a status can only ever be applied to a commit whose owning stack matches the payload's authenticated repository.

### Proof of Concept
Minitest plan (ActiveSupport::TestCase), no live GitHub:
1. Create two `Stack`/`Repository` fixtures, `stack_a` (repo `org-a/app`) and `stack_b` (repo `org-b/app`), simulating a fork relationship.
2. Create `commit_a = Commit.create!(stack: stack_a, sha: 'deadbeef'*5)` and `commit_b = Commit.create!(stack: stack_b, sha: 'deadbeef'*5)` (identical sha, different stacks) — establishing the two sides of the equality: `commit_b.stack.repository.full_name` ("org-b/app") vs the payload's `repository.full_name` ("org-a/app").
3. Build a payload: `{ 'sha' => commit_a.sha, 'state' => 'success', 'repository' => { 'full_name' => 'org-a/app', 'owner' => { 'login' => 'org-a' } } }`.
4. Call `Shipit::Webhooks::Handlers::StatusHandler.call(payload)` directly (bypassing the controller, as HMAC verification is out of scope for this handler-level test).
5. Assert `commit_b.statuses.count` increased (`commit_b.reload.statuses.count == 1`) even though the payload's `repository.full_name` ("org-a/app") never equals `commit_b.stack.repository.full_name` ("org-b/app") — demonstrating the binding is broken and a status is written for a repository/stack that never authenticated the payload.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L15-38)
```ruby
        def self.call(params)
          new(params).process
        end

        attr_reader :params, :payload

        def initialize(payload)
          @payload = payload
          @params = self.class.param_parser.parse!(payload)
        end

        def process
          raise NotImplementedError
        end

        private

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

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
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
