### Title
Webhook signature verified against the payload's `repository.owner.login` while all event handlers act on `repository.full_name` - cross-organization stack manipulation via webhook - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to validate an inbound webhook's HMAC signature against by reading `repository.owner.login` (or `organization.login`) out of the **same untrusted JSON body** it is about to validate. Once the signature check passes, every event handler (`PushHandler`, `StatusHandler`, `MembershipHandler`, PR handlers, etc.) resolves the target `Stack`/`Repository`/`Commit` using a *different* field from that body — `repository.full_name` (or bare `sha`, for statuses) — with no re-check that it belongs to the same organization whose secret authenticated the request. In a multi-tenant Shipit deployment (explicitly supported, see `test/dummy/config/secrets_double_github_app.yml` with `OrgOne`/`OrgTwo`, each with its own `github.webhook_secret`), a party who legitimately holds the webhook secret for one tenant's GitHub App can forge a request whose `repository.owner.login` matches their own org (so it authenticates) but whose `repository.full_name` names a stack belonging to a different tenant, letting them drive that other tenant's stacks.

### Finding Description
The trust binding that should hold is:
`organization authenticated by verify_signature == organization whose repository/stack is mutated by the handler`

`WebhooksController#verify_signature` computes the authentication key from the payload itself: [1](#0-0) [2](#0-1) 

`repository_owner` is taken from `params.dig('repository', 'owner', 'login')`, and is used purely to pick which configured `GitHubApp`/`webhook_secret` to HMAC-verify the raw body against, via `Shipit.github(organization: repository_owner)` → `verify_webhook_signature`: [3](#0-2) 

Nothing ties this `organization` selection to what the handler subsequently acts on. Every handler resolves its target repository from a *separate* field in the same attacker-controlled JSON — `repository.full_name` — via `Handler#repository_name`/`#stacks`: [4](#0-3) 

and `Repository.from_github_repo_name` blindly splits that string into `owner`/`name` and looks up any repository row, with no comparison to `repository_owner` used for signature verification: [5](#0-4) 

Because `owner.login` and `full_name` are two independent keys inside the same JSON body that the attacker fully controls once they can produce a valid HMAC for *some* configured organization, they can set `repository.owner.login = "attacker-org"` (to select the app the attacker's own webhook secret belongs to) while setting `repository.full_name = "victim-org/some-other-repo"` (to target a completely different tenant's `Stack`). For example `PushHandler` then does: [6](#0-5) 
which enqueues `stack.sync_github(expected_head_sha: ...)` — driving `GithubSyncJob` to append commits and re-cache the deploy spec for a stack the attacker does not own: [7](#0-6) 

`StatusHandler` is even weaker: it does not filter by repository at all, matching any `Commit` in the whole installation by bare `sha`: [8](#0-7) 
allowing an authenticated-for-one-org attacker to inject/forge CI statuses for commits belonging to a different tenant's stacks, which can gate/unblock `ci.require` checks used by continuous deployment.

This is the same class of bug flagged in the report: a value the recipient trusts to bind an operation to an authorization scope (`_toAddress`/callback destination in the report vs. the `owner.login` used to select the signing secret here) is not actually cross-checked against the value that the sensitive action is performed on (minted tokens sent to the real recipient vs. `full_name`/`sha` used to pick the real target stack/commit here) — the verification and the effect are decoupled, letting one authorized boundary bleed into another.

### Impact Explanation
This crosses the "escalation into cross-repository writes / unauthorized deploy" bar: a webhook signature valid for tenant A's GitHub App can be used to enqueue `GithubSyncJob` against a `Stack` belonging to tenant B, mutate its commit graph, invalidate/rebuild its cached deploy spec, and (via `StatusHandler`) forge/alter commit statuses on tenant B's commits — potentially unblocking `ci.require` gates that continuous-deployment logic relies on to allow a deploy. This is a cross-tenant integrity violation in a multi-organization Shipit installation, matching the "cross-repository writes" / "unauthorized deploy" impact tier.

### Likelihood Explanation
Exploitation requires the attacker to already legitimately control a webhook secret for at least one organization configured in the Shipit instance (i.e., they administer a GitHub App installation for some tenant on that Shipit deployment) — they need no Shipit account, `ApiClient` token, or repository write access to the *victim* org/repo. Multi-tenant configuration is a documented, supported deployment mode (`test/dummy/config/secrets_double_github_app.yml`, `docs/setup.md`), so this is not a hypothetical configuration. Within that scope, forging the raw JSON body and computing a valid HMAC with their own known secret is trivial — no cryptographic weakness needs to be broken, only the missing owner/full_name cross-check needs to be exploited.

### Recommendation
After `verify_signature` succeeds, re-derive `repository_owner` inside each `Handler` from the same trusted value used for signature verification (or pass it explicitly into the handler) and assert it matches the owner portion of `repository.full_name` (and, for `StatusHandler`, scope the `Commit` lookup to stacks belonging to that verified owner) before performing any lookup or mutation. Reject the webhook if the two disagree.

### Proof of Concept
1. Deploy Shipit configured for two tenants, `OrgA` and `OrgB`, each with its own GitHub App and `webhook_secret` (per `docs/setup.md`/`secrets_double_github_app.yml`).
2. As an operator/holder of `OrgA`'s `webhook_secret` (no access to `OrgB`), craft a `push` event JSON body:
   ```json
   {
     "ref": "refs/heads/main",
     "after": "<attacker-chosen sha>",
     "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/victim-repo" }
   }
   ```
3. Compute `X-Hub-Signature: sha1=<HMAC-SHA1(body, OrgA_webhook_secret)>` and POST it to `/webhooks` with `X-Github-Event: push`.
4. `verify_signature` resolves `repository_owner = "OrgA"`, verifies successfully against `OrgA`'s secret.
5. `PushHandler#process` resolves `stacks` via `Repository.from_github_repo_name("OrgB/victim-repo")`, finds `OrgB`'s stack, and enqueues `GithubSyncJob` for it — despite the request only being authenticated for `OrgA`.

**Note:** I could not fully trace whether any additional guard exists further downstream (e.g., in `Stack#sync_github` or `CacheDeploySpecJob`) that might re-validate the organization before mutating state, since those files were outside what I retrieved. If such a check exists, it would mitigate the impact of this specific handler but the underlying missing binding in `WebhooksController`/`Handler` would remain across all other handlers (`StatusHandler`, `MembershipHandler`, PR handlers) shown above.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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

**File:** app/jobs/shipit/github_sync_job.rb (L18-49)
```ruby
    def perform(params)
      @stack = Stack.find(params[:stack_id])
      expected_head_sha = params[:expected_head_sha]
      retry_count = params[:retry_count] || 0
      head_before_sync = spec_cache_target
      appended_commits = []

      handle_github_errors do
        new_commits, shared_parent = fetch_missing_commits { stack.github_commits }

        # Retry on Github eventual consistency: webhook indicated new commits but we found none
        if expected_head_sha && new_commits.empty? && !commit_exists?(expected_head_sha) &&
           retry_count < MAX_RETRY_ATTEMPTS
          GithubSyncJob.set(wait: RETRY_DELAY * retry_count).perform_later(params.merge(retry_count: retry_count + 1))
          return
        end

        stack.transaction do
          shared_parent&.detach_children!
          appended_commits = new_commits.map do |gh_commit|
            append_commit(gh_commit)
          end
          stack.lock_reverted_commits! if appended_commits.any?(&:revert?)
        end
      end
      sync_changed_nothing = appended_commits.empty? &&
                             spec_cache_target == head_before_sync &&
                             stack.cached_deploy_spec.present?
      return if sync_changed_nothing && !params[:force_spec_cache]

      CacheDeploySpecJob.perform_later(stack)
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
