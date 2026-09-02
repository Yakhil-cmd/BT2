### Title
Unauthenticated cross-organization webhook forgery via unbound `repository.owner.login` vs `repository.full_name` fields when a GitHub App's `webhook_secret` is unset - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`Shipit::WebhooksController#verify_signature` selects which GitHub App/organization secret to validate an incoming webhook against using `repository.owner.login` (falling back to `organization.login`), then unconditionally passes the entire parsed JSON body to event handlers, which instead key all data lookups off `repository.full_name`. These are two independent, attacker-influenceable fields inside the same JSON body. When any configured GitHub App organization has no `webhook_secret` (an explicitly supported, documented configuration), signature verification becomes a no-op for that organization, and nothing then re-validates that `repository.full_name` actually belongs to that organization — allowing forged events to target any stack tracked by Shipit.

### Finding Description
`verify_signature` resolves the GitHub App to check the signature against purely from the attacker-supplied payload: [1](#0-0) [2](#0-1) 

`GithubApp#verify_webhook_signature` is a **complete bypass** when `webhook_secret` is blank: [3](#0-2) 

`webhook_secret` is explicitly documented and supported as optional, both in setup docs and in example secrets files: [4](#0-3) [5](#0-4) 

Once `verify_signature` passes (trivially, for an org with no secret configured), `create` hands the **entire raw JSON body** to the registered handlers for the event: [6](#0-5) 

Critically, the handlers do not use `repository.owner.login` (the field that gated signature verification) — they resolve the target repository/stack from `repository.full_name`: [7](#0-6) [8](#0-7) 

This breaks the binding: **organization authenticated (via `repository.owner.login`/`organization.login` and the org's `webhook_secret`) ≠ repository actually written to (via `repository.full_name`)**. Since `verify_signature` never checks that `full_name`'s owner matches `repository_owner`, and since the signature check itself is a no-op whenever the resolved org's secret is unset, an attacker who knows (or guesses) that any org configured in the Shipit instance's multi-org `github:` config has no `webhook_secret` can submit a POST to `/webhooks` with:
- `X-Github-Event` set to any handled event (`push`, `status`, `check_suite`, `membership`, `pull_request`)
- `repository.owner.login` (or `organization.login`) set to the secret-less org, to sail through `verify_signature`
- `repository.full_name` set to **any other tracked stack's repository**, e.g. `"Shopify/shipit-engine"`

The `PushHandler` will then invoke `stack.sync_github(expected_head_sha: params.after)` on the real target stack, using an `after` SHA fully controlled by the attacker: [9](#0-8) 

This enqueues `GithubSyncJob`, which fetches commits from the real GitHub repository via the app's own authenticated GitHub App token and updates the stack's commit list, which for continuously-deployed stacks feeds directly into automatic deploys: [10](#0-9) 

The same field confusion applies to `status` (forging CI green light for a commit) and `check_suite` (forging check completion) events on repositories/stacks that belong to organizations with a properly configured secret, entirely by riding on another, secret-less org's identity.

### Impact Explanation
This crosses the "organization authenticated versus the repository that is written" trust boundary explicitly called out as in-scope. An unprivileged attacker (no Shipit session, no `ApiClient`, no `webhook_secret`, no repository write access to the *target* repo — only knowledge that some configured org lacks a webhook secret) can:
- Trigger `GithubSyncJob` for arbitrary tracked stacks, forcing new-commit ingestion and, on stacks with continuous deployment enabled, **an unauthorized deploy**.
- Forge `status`/`check_suite` events to make gating CI checks appear green for arbitrary commits on arbitrary tracked repositories, bypassing merge/deploy safety gates.
This satisfies the Critical bar ("an unauthorized deploy") and the High bar ("unauthenticated read/write of stack state").

### Likelihood Explanation
The precondition — at least one org in a multi-org `github:` configuration lacking `webhook_secret` — is explicitly presented as an acceptable, "optional" setup in the project's own documentation and example secrets files, so it is realistic in real deployments. No credentials, sessions, or repository access are required to exploit it once that precondition holds; it is a single unauthenticated HTTP POST.

### Recommendation
- In `Shipit::WebhooksController#verify_signature`, do not treat a missing `webhook_secret` as automatic success; make webhook secrets mandatory (or explicitly reject bodies whose `repository.full_name` owner does not case-insensitively match the organization whose secret validated the signature).
- Cross-validate `repository.owner.login` (or `organization.login`) against `repository.full_name`'s owner segment before dispatching to handlers, rejecting mismatches with `422`.
- Consider deriving the target stack/repository from the same field used for authentication rather than an independent field controlled by the same untrusted payload.

### Proof of Concept
Preconditions: Shipit instance configured with multiple GitHub orgs (per `docs/setup.md` "Using Multiple Github Applications"), where org `EmptySecretOrg` has `webhook_secret: nil` and org `Shopify` (or any other tracked org) has stacks under continuous deployment.

```
POST /webhooks HTTP/1.1
X-Github-Event: push
Content-Type: application/json

{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-or-real-sha-on-target-repo>",
  "repository": {
    "owner": { "login": "EmptySecretOrg" },
    "full_name": "Shopify/shipit-engine"
  }
}
```

- `verify_signature` calls `Shipit.github(organization: "EmptySecretOrg")`, whose `webhook_secret` is `nil`, so `verify_webhook_signature` returns `true` unconditionally — no `X-Hub-Signature` header is even required.
- `PushHandler` resolves `stacks` via `Repository.from_github_repo_name("Shopify/shipit-engine")`, finds the real stack, and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")`, triggering `GithubSyncJob` and, if continuous deployment is enabled, an unauthorized deploy of that commit.

Note: I could not directly execute this request against a running instance from this environment (no filesystem/terminal/browser access here); the flow above is derived purely from static analysis of the cited source files. Confirming this in a live/test environment would require starting a Devin session with runtime access.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** docs/setup.md (L29-30)
```markdown
  - Webhook URL: It must be set to `<homepage>/webhooks`, e.g. `https://example.com/webhooks`.
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
```

**File:** config/secrets.development.example.yml (L8-17)
```yaml
github:
  app_id:
  installation_id:
  webhook_secret: # nil
  private_key:
  oauth:
    id:
    secret:
    teams: # Optional

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
