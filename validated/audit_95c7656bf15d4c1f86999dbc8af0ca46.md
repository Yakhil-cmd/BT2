Found the binding break. The webhook signature is verified against the GitHub App configured for the organization derived from `repository.owner.login` (or `organization.login`), but the handler that actually acts on the payload looks up the target `Repository`/`Stack` using `repository.full_name` — a completely different field that is never checked against the signing organization.

### Title
Webhook signature verification authenticates the payload's `repository.owner.login` organization while handlers act on the unrelated `repository.full_name` field - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/handler.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to HMAC-verify the request against using `repository_owner`, which reads `params.dig('repository', 'owner', 'login')` (falling back to `organization.login`). Once the signature check passes, `WebhooksController#create` hands the *entire* parsed JSON body to `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }`. Handlers such as `PushHandler`/`StatusHandler`/`CheckSuiteHandler` (via the shared `Handler#stacks`/`Handler#repository_name`) resolve the target `Repository` using `payload.dig('repository', 'full_name')` — a separate, independently attacker-influenced field within the same JSON body that is never cross-checked against `repository.owner.login`.

### Finding Description
`verify_signature` in [1](#0-0)  computes `repository_owner` from `params.dig('repository', 'owner', 'login')` or `params.dig('organization', 'login')` ( [2](#0-1) ) and uses it solely to pick which `GitHubApp` (and thus which `webhook_secret`) validates the HMAC signature ( [3](#0-2) ). This field is one small, attacker-writable JSON key nested in the raw body that is itself covered by the HMAC — so an attacker cannot forge a signature for an organization whose secret they don't know.

However, the actual dispatch to handlers passes the raw, fully attacker-controlled `params` unchanged ( [4](#0-3) ), and the base `Handler` class resolves the repository to act on via `payload.dig('repository', 'full_name')` ( [5](#0-4) ) — a different field from `repository.owner.login`. Nothing in the engine asserts `repository.full_name` starts with (or is owned by) `repository.owner.login`.

In multi-organization deployments (`Shipit.github(organization:)` per `lib/shipit.rb` `github_app_config`, [6](#0-5) ), this means: the binding the engine implicitly relies on is `organization authenticated by webhook_secret == organization owning the repository whose Stack is mutated`. Since the payload is signed as a whole (the HMAC covers the full raw body, including both `repository.owner.login` and `repository.full_name`), an attacker cannot simply edit `full_name` post-signing without invalidating the signature — they would need a valid signature for *some* organization they legitimately control (i.e., they have push/webhook delivery access to a repo under organization A, whose `webhook_secret` they therefore can produce valid signatures for via GitHub's own delivery), but then craft `repository.full_name` to reference a `Repository`/`Stack` registered under organization B in the same Shipit instance.

Concretely: if organization A and organization B are both configured in the same `secrets.yml` `github:` multi-org block (as documented in `docs/setup.md` lines 182–209), and organization A has *any* repository with Shipit webhooks enabled, a user who can trigger/replay a webhook from a repository under org A (e.g. by renaming/forking, or via a compromised/malicious repo under org A that they administer) can shape the JSON payload's `repository.full_name` to point at a `org-b/some-repo` Stack, and the signature — verified only against org A's secret — will pass, letting `PushHandler`, `StatusHandler`, `CheckSuiteHandler`, etc. act on org B's stack (e.g., queue `GithubSyncJob`, create commit statuses, trigger `RefreshCheckRunsJob`) despite never having org B's secret.

### Impact Explanation
This crosses the "authenticated organization != repository written" boundary explicitly called out in the rules. The practical effect is cross-repository/cross-organization webhook forgery: an attacker with legitimate (even low-privilege) webhook delivery capability on org A's repo can inject fabricated push/status/check-suite events against org B's Stack records, causing spurious `GithubSyncJob`/`RefreshCheckRunsJob` runs, corrupted commit statuses, or (via `PushHandler`'s `sync_github`) triggering continuous-deployment sync logic against the wrong stack. This does not by itself grant RCE or `GITHUB_TOKEN` exfiltration, but it does allow cross-repository writes to Shipit's internal state (statuses, commits, task scheduling) — matching the "cross-repository writes" Critical criterion, contingent on the deployment using the documented multi-organization `github:` config.

### Likelihood Explanation
Requires: (1) the host application configured with multiple GitHub organizations sharing one Shipit instance (a documented, supported configuration), and (2) attacker control (or ability to trigger a webhook delivery) for at least one repository under one of those configured organizations. This is a real but non-default configuration dependency — single-organization deployments (the default/most common setup) are not affected, since `repository_owner` and the actual acting repository would necessarily belong to the same, single configured organization.

### Recommendation
In `Handler#repository_name` / `Handler#stacks`, or in `WebhooksController#verify_signature`, assert that the resolved `repository.owner.login` (used to select the signing organization) matches the owner segment of `repository.full_name` before dispatching to handlers. Reject the webhook (422) if they diverge.

### Proof of Concept
Conceptual, not exploitable/testable without a live multi-org secrets.yml and two configured GitHub orgs:
1. Configure `secrets.yml` with two orgs, `org-a` and `org-b`, each with its own `webhook_secret`, per `docs/setup.md`'s multi-org example.
2. Have a Shipit-connected repo `org-b/target-repo` with an existing `Stack`.
3. As an entity that controls a repo under `org-a` (and thus can produce/replay a validly-signed delivery using `org-a`'s `webhook_secret`), craft a `push` event JSON body where `repository.owner.login == "org-a"` (so `Shipit.github(organization: "org-a")` is used for signature verification) but `repository.full_name == "org-b/target-repo"`.
4. Sign the raw body with `org-a`'s webhook secret and POST to `/github/webhooks` with header `X-Hub-Signature`.
5. `verify_signature` passes (org A's secret matches), `PushHandler#stacks` resolves `Repository.from_github_repo_name("org-b/target-repo")` and calls `stack.sync_github` on org B's stack — despite the request never having been authenticated by org B's secret.

Note: I could not find any explicit cross-org isolation check in the codebase, and no test in `test/controllers/webhooks_controller_test.rb` exercises the multi-org case, so this analog's presence has not been contradicted by any guard I found; however, I also could not fully verify end-to-end runtime behavior (e.g., whether `Repository.from_github_repo_name` or `Stack` lookups apply any implicit organization scoping elsewhere) within the available index — a full Devin session with repo access would be needed to confirm there is no additional scoping layer.

### Citations

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

**File:** lib/shipit.rb (L196-200)
```ruby
  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
  end
```
