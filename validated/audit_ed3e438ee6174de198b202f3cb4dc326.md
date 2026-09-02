### Title
Cross-repository/cross-organization commit status forgery via unscoped SHA lookup in webhook status handling - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` updates commit CI status by matching solely on the commit SHA, globally across the entire Shipit installation, instead of scoping the lookup to the repository whose organization's webhook secret was used to verify the incoming request. This breaks the binding "organization whose signature authenticated the request == repository/stack being written."

### Finding Description
The webhook signature is verified per-organization: `WebhooksController#verify_signature` resolves `Shipit.github(organization: repository_owner)` from the payload's `repository.owner.login` and validates the HMAC over the raw body with that organization's `webhook_secret`. [1](#0-0) [2](#0-1) 

Once verified, the payload is dispatched to handlers with no re-validation that the handler acts only on the same organization/repository whose secret signed the request: [3](#0-2) 

Most handlers correctly scope their side effects to the signing repository via `Handler#stacks`, which filters by `Repository.from_github_repo_name(repository_name)` (i.e. `payload.dig('repository', 'full_name')`), as seen in `PushHandler#process` and `CheckSuiteHandler#process`: [4](#0-3) [5](#0-4) [6](#0-5) 

However, `StatusHandler#process` never calls `stacks`/`repository_name` at all — it queries `Commit.where(sha: params.sha)` globally, across every repository and every organization tracked by the Shipit instance, and mutates the status of every match: [7](#0-6) 

Since Git SHAs are content-addressed, the same commit SHA legitimately exists in multiple repositories that share history (forks, mirrors, subtree-merged repos, or any repo containing a cherry-picked/rebased commit with an unmodified tree+parents). An attacker who is a legitimate GitHub App/webhook sender for **their own** organization/repository — e.g., they push a commit or otherwise trigger a `status` event on a repo whose webhook secret verifies correctly — can cause a status webhook, verified with *their own organization's* `webhook_secret`, to be applied to *any other organization's stack* whose tracked repository happens to share that SHA. This directly breaks the "organization authenticated vs. repository written" equality: `verified_organization(payload) == Shipit.github(organization: repository_owner)` while the actual write touches `Commit ∈ any_stack.repository`, unconstrained by `repository_owner`.

### Impact Explanation
Commit status directly gates deploy eligibility and merge-queue eligibility across the codebase: `Commit#deployable?` depends on `success?` and `blocked?`, both derived from `Status::Common#blocking?`/`#required?`, which are populated by exactly the statuses `StatusHandler` writes. [8](#0-7) [9](#0-8) 

An attacker controlling a `status` webhook signed by any single organization onboarded to the Shipit instance can flip a shared-SHA commit's CI status to `success` in a target organization's stack that they have no access to, unblocking or accelerating an unauthorized deploy/merge decision in that other organization — i.e., an unauthorized deploy driven by cross-organization write, matching the "High"/"Critical" impact bar for unauthorized deploy via cross-repository writes. This requires no `webhook_secret` of the victim organization, no `ApiClient` token, and no GitHub write access to the victim repository — only ordinary push/CI access to any org already installed on the shared Shipit instance and a commit that shares a SHA with the target (forks and shared-history repos make this practically achievable).

### Likelihood Explanation
Medium-High in any multi-tenant Shipit deployment (multiple GitHub organizations/apps configured under one `Shipit.github(organization:)` mapping, as documented in `docs/setup.md`). The attacker only needs standard, unprivileged control of one onboarded organization/repo (e.g., their own fork) to produce a signed `status` webhook for a SHA that also exists in a victim stack's repository history. No secrets, tokens, or elevated GitHub permissions for the victim org are required.

### Recommendation
Scope `StatusHandler#process` to the signing repository the same way other handlers do: restrict the `Commit` lookup via `stacks` (i.e., filter by `Repository.from_github_repo_name(payload.dig('repository', 'full_name'))`) rather than a bare, cross-tenant `Commit.where(sha: ...)`, e.g. `stacks.flat_map(&:commits).select { |c| c.sha == params.sha }.each { ... }` or add a `stack_id`/`repository_id` join constraint to the query.

### Proof of Concept
1. Configure Shipit with two organizations, `victim-org` (tracking `victim-org/app`) and `attacker-org` (tracking `attacker-org/app-fork`, a fork of `victim-org/app` sharing commit history), each with its own installed GitHub App and `webhook_secret`, per `docs/setup.md`.
2. Attacker pushes/CI-triggers a `status` event on `attacker-org/app-fork` for a commit SHA `abc123` that is also present in `victim-org/app` (inherited via the fork's shared history).
3. GitHub signs and delivers the webhook using `attacker-org`'s `webhook_secret`; `WebhooksController#verify_signature` resolves `Shipit.github(organization: 'attacker-org')` and verifies successfully since the signature is valid for that organization.
4. `StatusHandler#process` executes `Commit.where(sha: 'abc123').each { |commit| commit.create_status_from_github!(params) }`, which matches and updates the corresponding commit row belonging to `victim-org/app`'s stack — a repository the attacker never authenticated against — potentially marking it `success` and unblocking `victim-org`'s deploy pipeline.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
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

**File:** app/models/shipit/commit.rb (L227-237)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end

    def blocked?
      return false if stack.blocking_statuses.empty?

      # TODO: Perfs might be horrible here if the range is big.
      # We should look at fetching the undeployed commits only once
      stack.commits.reachable.newer_than(stack.last_deployed_commit).older_than(self).any?(&:blocking?)
    end
```

**File:** app/models/shipit/status/common.rb (L46-52)
```ruby
      def blocking?
        !success? && commit.blocking_statuses.include?(context)
      end

      def required?
        commit.required_statuses.include?(context)
      end
```
