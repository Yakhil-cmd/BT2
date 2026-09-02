### Title
Cross-repository commit-status forgery via unscoped `Commit.where(sha:)` lookup in `StatusHandler` - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`WebhooksController#verify_signature` authenticates an inbound GitHub `status` webhook against the GitHub App/organization derived from the payload's `repository.owner.login` (or `organization.login`) field, but the handler that acts on the payload — `Shipit::Webhooks::Handlers::StatusHandler` — never re-checks that binding when writing state. It resolves target commits purely by `sha`, globally, across every stack/repository tracked by the Shipit instance.

### Finding Description
The webhook signature check establishes the equality: `signing_org == payload.repository.owner.login`, i.e. it only proves the request truly came from GitHub for *that* organization/repository: [1](#0-0) [2](#0-1) 

Once verified, the raw parsed `params` are handed to every registered handler for the event with no further scoping: [3](#0-2) 

`StatusHandler#process`, however, breaks the binding: it looks up commits by `sha` alone, with no filter on `payload.dig('repository', 'full_name')` or the organization that was actually authenticated: [4](#0-3) 

Contrast this with the base `Handler` class, which *does* provide a repository-scoped `stacks` helper (`Repository.from_github_repo_name(repository_name)&.stacks`) used correctly by other handlers such as `PushHandler`: [5](#0-4) [6](#0-5) 

`StatusHandler` never calls this helper, so it writes a `Status` to `commit.create_status_from_github!` on any `Commit` record in the database that happens to share the given `sha` — regardless of which repository/stack that commit belongs to: [7](#0-6) 

Because git commit SHAs are content-addressed, two different repositories tracked by the same Shipit instance can legitimately share identical commit SHAs (e.g. a fork sharing history with its upstream, or a repository imported/rebased from another). The binding that should hold is: `organization authenticated by verify_signature == repository whose Commit rows are mutated`. `StatusHandler` breaks this equality — the write target is selected by `sha` matching across *all* repositories, not by the authenticated repository/organization.

### Impact Explanation
A commit's aggregate `status` feeds directly into `Commit#deployable?`, which gates both manual deploys (CI-required checks) and `continuous_deployment`: [8](#0-7) [9](#0-8) 

An attacker who legitimately controls a repository/organization onboarded to the same Shipit instance (a fork, a repo they administer, or one where they can create arbitrary commit-status webhooks through normal GitHub CI integrations) can send a genuinely GitHub-signed `status` event for *their own* repository referencing a commit SHA that is shared with a victim repository's stack. Because `StatusHandler` matches by `sha` alone, this forges a `success` status on the victim's commit, satisfying `required_statuses`/CI gating and enabling an unauthorized deploy or continuous-deployment trigger on a repository the attacker never had write access to. This crosses the "unauthorized deploy" impact bar for High severity in this engine.

### Likelihood Explanation
This does not require compromising any secret, `ApiClient` token, or GitHub App key — only ordinary write/CI access to one onboarded repository whose commit history overlaps (shared SHAs) with a target stack, which is common for forks and repositories with shared ancestry. The webhook signature check passes normally because the request is authentically from GitHub for the attacker's own repository; the vulnerability is purely in the missing repository scoping inside `StatusHandler`, making exploitation deterministic once a shared SHA exists.

### Recommendation
Scope `StatusHandler#process` to the repository identified in the signed payload, mirroring the base `Handler#stacks` helper, e.g. restrict the `Commit` lookup to `stacks.map(&:commits)` (commits belonging to stacks under `Repository.from_github_repo_name(payload.dig('repository', 'full_name'))`) instead of a bare `Commit.where(sha: params.sha)` across the whole instance.

### Proof of Concept
1. Attacker administers/CI-integrates `attacker/fork`, which is a fork of `victim/upstream` sharing a common ancestor commit `abc123...` (present in both repositories' git history and both tracked as Shipit stacks).
2. Attacker sets a commit status (`success`) on `abc123...` in `attacker/fork` via any legitimate CI tool with repo write access — a completely normal action within their own repo.
3. GitHub sends a `status` webhook to Shipit, signed with `attacker/fork`'s (org's) webhook secret; `WebhooksController#verify_signature` validates it successfully because it only checks the signature against the organization named in the payload.
4. `StatusHandler#process` executes `Commit.where(sha: 'abc123...')`, which matches the corresponding commit row belonging to `victim/upstream`'s stack (same SHA), and calls `create_status_from_github!`, writing a forged `success` status onto the victim's commit.
5. If `victim/upstream`'s stack requires that CI context and has `continuous_deployment` enabled, this forged status can trigger `ContinuousDeliveryJob`/gate a manual deploy — an unauthorized deploy of the victim repository triggered entirely from the attacker's own repository's webhook traffic.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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

**File:** app/models/shipit/commit.rb (L281-287)
```ruby
    def schedule_continuous_delivery
      return unless deployable? && stack.continuous_deployment? && stack.deployable?

      # This buffer is to allow for statuses and checks to be refreshed before evaluating if the commit is deployable
      # - e.g. if the commit was fast-forwarded with already passing CI.
      ContinuousDeliveryJob.set(wait: RECENT_COMMIT_THRESHOLD).perform_later(stack)
    end
```
