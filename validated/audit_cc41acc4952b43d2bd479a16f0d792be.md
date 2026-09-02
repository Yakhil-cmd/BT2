## Title
`StatusHandler` writes a GitHub `status` event to any commit with a matching SHA without validating that the payload's `repository` belongs to that commit's stack, breaking the org-that-authenticated vs. repository-that-is-written binding - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
The H-21 bug class is "a value/field is used to satisfy a security check, but a *different, unbound* value is what actually gets acted on" (the auction-end duration used for the `claim()` gate never matched the value actually driving epoch progression). In this engine, `WebhooksController#verify_signature` selects which organization's `webhook_secret` to verify the inbound signature against using the payload's `repository.owner.login` (falling back to `organization.login`), but `Shipit::Webhooks::Handlers::StatusHandler#process` never re-checks that binding when deciding which `Commit` to mutate — it looks up commits globally by `sha` alone.

### Finding Description
`WebhooksController#verify_signature` picks the GitHub App/org config to verify the HMAC signature against based on the payload's own `repository.owner.login`: [1](#0-0) [2](#0-1) 

Every other handler that acts on repository-scoped state re-derives its target strictly from `payload.dig('repository', 'full_name')` via the shared `stacks` helper: [3](#0-2) 

`PushHandler` and `CheckSuiteHandler` correctly go through this `stacks` scoping: [4](#0-3) [5](#0-4) 

`StatusHandler`, however, never calls `stacks` or inspects `payload['repository']` at all — it updates every `Commit` row whose `sha` matches the payload's `sha`, globally, across every stack/repository tracked by this Shipit instance: [6](#0-5) 

`Commit` rows are only ever unique in practice per `stack_id` (uniqueness scoping only appears via `stack`-relative helpers like `children`), not globally, and `sha` is not declared unique at the model layer: [7](#0-6) [8](#0-7) 

So the equality the design intends is:
`organization whose webhook_secret verified this request == owner of the repository whose commit is mutated`

But the code only enforces: `organization whose webhook_secret verified this request == payload['repository']['owner']['login']` (used solely for signature lookup), while `StatusHandler` enforces nothing that ties the mutated `Commit` back to that same repository/org — it is selected purely by `sha`, a value that is not covered by any per-repository scoping check.

### Impact Explanation
On any multi-tenant Shipit deployment (a single Shipit instance with the GitHub App installed across multiple organizations, each with its own `webhook_secret` per `Shipit.github(organization:)` config), an actor who legitimately controls one onboarded organization/repo can cause GitHub to emit a real, correctly-signed `status` webhook for their own repo/commit while choosing an arbitrary `sha` value in that payload. Because `StatusHandler` resolves the target purely via `Commit.where(sha: params.sha)` with no repository check, that status is applied to any `Commit` record elsewhere in the instance that happens to share the same SHA — i.e., a commit belonging to a completely different tracked repository/organization. Since Shipit gates deploys on commit status via `ci.require`/`deployable?`, this can be used to forge a passing CI status on a commit under another organization's stack, which can subsequently allow that commit to be picked up as `deployable?` for deploy/merge automation — an unauthorized deploy path driven purely by cross-tenant status confusion. This satisfies the "Critical – unauthorized deploy" bar defined in scope, though full exploitability further depends on being able to reference/predict a target SHA in another tenant's stack (feasible for any public target commit, since SHAs are public data).

### Likelihood Explanation
Requires no Shipit session, API token, or webhook secret — only the ability to be the legitimate owner/admin of any one organization/repo that this shared Shipit instance already trusts (a pattern this engine explicitly documents supporting for OSS/multi-org setups). It does not require compromising GitHub's signature scheme, since the attacker's own org's webhook secret genuinely signs their own event. The only extra step is knowledge of a target SHA in a different tracked repository, which is public information for any public commit.

### Recommendation
`StatusHandler#process` should resolve target commits the same way every other handler does — scoped through `stacks`/`payload['repository']['full_name']` — instead of a bare global `Commit.where(sha: params.sha)` lookup, e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` or an equivalent join that requires the commit's `stack.repository` to match the payload's `repository` used for the signature verification.

### Proof of Concept
1. Deploy one Shipit instance configured for two orgs/installations, `org-a` (attacker-controlled) and `org-b` (victim), each with distinct `webhook_secret`s per `Shipit.github(organization:)`.
2. Shipit tracks `org-b/victim-repo` stack with a pending commit `deadbeef...` awaiting a required CI status (`ci.require`).
3. As admin of `org-a`, trigger (or directly call the GitHub Statuses API for) a `status` event on any commit in `org-a/attacker-repo`, but set the payload's `sha` field to `deadbeef...` (the target commit hash in `org-b`'s repo) — GitHub signs this webhook with `org-a`'s webhook secret since it's a real event for `org-a`'s repo.
4. `WebhooksController#verify_signature` resolves `repository_owner` = `org-a` from `payload['repository']['owner']['login']` and successfully verifies against `org-a`'s secret.
5. `StatusHandler#process` executes `Commit.where(sha: 'deadbeef...')`, matching the `Commit` row belonging to `org-b`'s stack (since lookup is unscoped by repository), and calls `create_status_from_github!`, injecting a forged status onto the victim's commit — potentially satisfying `ci.require` and enabling that commit to become `deployable?` in `org-b`'s stack without ever touching `org-b`'s real CI or credentials.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-31)
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

**File:** app/models/shipit/commit.rb (L11-16)
```ruby
    belongs_to :stack
    has_many :statuses, -> { order(created_at: :desc) }, dependent: :destroy, inverse_of: :commit
    has_many :check_runs, -> { order(created_at: :desc) }, dependent: :destroy, inverse_of: :commit
    has_many :commit_deployments, dependent: :destroy
    has_many :release_statuses, dependent: :destroy
    belongs_to :merge_request, inverse_of: :merge_commit, optional: true
```

**File:** app/models/shipit/commit.rb (L239-241)
```ruby
    def children
      self.class.where(stack_id:).newer_than(self)
    end
```
