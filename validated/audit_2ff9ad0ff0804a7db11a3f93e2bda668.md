### Title
`StatusHandler#process` writes GitHub status to every commit sharing a SHA regardless of repository - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` looks up commits with `Commit.where(sha: params.sha)` with no repository/stack scoping, unlike sibling handlers (e.g. `CheckSuiteHandler`) which resolve the acting repository via `Repository.from_github_repo_name(repository_name)` before touching any records. Any status payload whose `sha` collides with a commit belonging to an unrelated stack (e.g. a fork sharing git history with a victim repo) will have its `context`/`state` written onto that victim commit via `Commit#create_status_from_github!`, potentially flipping `deployable?`/merge eligibility for a repository that never authenticated the event.

### Finding Description
The invariant that should hold is: `commit.stack.repository.full_name == payload['repository']['full_name']` for every `Commit` record mutated while processing a given webhook. That invariant is enforced in `CheckSuiteHandler#process`, which scopes through `stacks` (derived from `Repository.from_github_repo_name(repository_name)` in `Handler#stacks`) before touching any commit: [1](#0-0) [2](#0-1) 

`StatusHandler#process`, however, queries `Commit` globally with no reference to `payload['repository']` at all: [3](#0-2) 

Each matched commit then has `create_status_from_github!(params)` called, which persists the status and re-evaluates deployability/merge eligibility via `add_status`: [4](#0-3) [5](#0-4) 

The `Commit` model has no repository-derived uniqueness constraint that would prevent two different stacks from holding rows with the identical `sha`; `Commit belongs_to :stack`, and SHA collisions are only "ambiguous" within a single stack's `by_sha` scope, not globally: [6](#0-5) [7](#0-6) 

Request path: attacker sends `POST /webhooks` with header `X-Github-Event: status` and a JSON body containing `repository.owner.login` matching an organization already configured in Shipit (so `verify_signature` in `WebhooksController` can succeed for that org), plus `sha`, `context: sonarqube`, `state: failure`. `WebhooksController#create` dispatches to every registered handler for the `status` event without ever restricting the handler's own record lookups to the requesting repository: [8](#0-7) [9](#0-8) 

`verify_signature` only proves that the payload was signed by the secret configured for the organization named in `repository.owner.login` of the *attacker's own* payload — it says nothing about which `Commit` rows the handler is permitted to touch. `StatusHandler` simply never consults `payload['repository']`, so it will happily mutate a `Commit` belonging to a completely different `Stack`/`Repository` if the `sha` happens to match, e.g. because the victim stack tracks a repository that is a fork of (or shares history with) the attacker's own onboarded repository. This is exactly the class of bug the codebase already guards against in `CheckSuiteHandler` via `Handler#stacks`, but the guard is absent in `StatusHandler`.

### Impact Explanation
A crafted `status` event from an attacker-controlled (but Shipit-configured) repository can overwrite the CI status for a commit belonging to an unrelated victim stack, as long as the SHA is shared (e.g., forked history, cherry-picked/rebased commits with identical hash, or coincidental reuse in test/staging environments that mirror upstream history). Because `create_status_from_github!` → `add_status` recomputes `status` and can trigger `stack.schedule_merges` or block merges depending on `ci.require`/`ci.blocking`/`ci.soft_failing` configuration on the victim stack, an attacker can set a required context (e.g. `sonarqube`) to `failure` and block the victim's merge/deploy pipeline, or set a blocking context to `success` to unblock it — cross-tenant state manipulation of a repository that never authenticated the request. This matches the Critical category: "a payload for one repository mutating another's stack, commit, task or team."

### Likelihood Explanation
The precondition of a shared SHA across two different tracked repositories is the limiting factor. This is realistic in git workflows involving forks (identical commit objects/hashes exist in both the upstream repo and any fork/mirror until history diverges), shared submodule/monorepo setups, or repositories that mirror each other. The attacker additionally needs their own repository/organization to be already configured in Shipit with a known signature setup they control (i.e., they must be able to produce a validly-signed `status` webhook for *some* organization Shipit trusts) — this is satisfiable by any onboarded repository owner, who is still "unprivileged" with respect to the victim stack. Given those preconditions, the attack is fully repeatable and requires only crafting one HTTP POST per attempt.

### Recommendation
Scope `StatusHandler#process` to the requesting repository the same way `CheckSuiteHandler` does: resolve `stacks` via `Repository.from_github_repo_name(repository_name)` (or otherwise derive the stack from `payload['repository']['full_name']`) and only query/update `Commit` rows belonging to that repository's stacks, e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` or `Commit.joins(stack: :repository).where(sha: params.sha, shipit_repositories: { ... })`.

### Proof of Concept
1. Seed two stacks, `victim_stack` (repository `victim/repo`, `ci.require` includes `sonarqube`) and `attacker_stack` (repository `attacker/fork`), each with a `Commit` row sharing the same `sha` (simulating shared git history).
2. Seed `victim_commit` with an existing successful `sonarqube` status so `victim_commit.deployable?` is `true`.
3. Directly invoke `Shipit::Webhooks::Handlers::StatusHandler.call(payload)` (bypassing HTTP/signature layer, per the engine's own handler unit-testing convention) with a payload whose `repository` points to `attacker/fork` but whose `sha` matches the shared SHA, `context: 'sonarqube'`, `state: 'failure'`.
4. Assert, before: `victim_commit.reload.deployable?` is `true` and `victim_commit.status.state` is `'success'` for context `sonarqube`.
5. Assert, after processing: `victim_commit.reload.deployable?` is `false` and the `sonarqube` status on `victim_commit` is `'failure'`, despite the webhook payload's `repository` being `attacker/fork`, not `victim/repo` — proving the equality `commit.stack.repository.full_name == payload['repository']['full_name']` is violated for `victim_commit`.

### Citations

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/commit.rb (L11-11)
```ruby
    belongs_to :stack
```

**File:** app/models/shipit/commit.rb (L92-99)
```ruby
    def self.by_sha(sha)
      raise AmbiguousRevision, "Short SHA1 #{sha} is ambiguous (too short)" if sha.to_s.size < 6

      commits = where('sha like ?', "#{sha}%").take(2)
      raise AmbiguousRevision, "Short SHA1 #{sha} is ambiguous (matches multiple commits)" if commits.size > 1

      commits.first
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

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
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
