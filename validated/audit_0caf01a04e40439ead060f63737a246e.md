Confirmed: `PushHandler#process` at [1](#0-0)  uses `stacks` (derived from `Handler#repository_name` = `payload.dig('repository', 'full_name')`) to find matching branch stacks and calls `stack.sync_github`, which enqueues `GithubSyncJob` — a job that fetches new commits and can drive continuous delivery deploys via `Commit#schedule_continuous_delivery` → `ContinuousDeliveryJob` → `Stack#trigger_continuous_delivery`.

I now have enough to produce the finding.

### Title
Cross-organization webhook forgery via `full_name` vs `owner.login` binding mismatch enables unauthorized deploy triggering - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which organization's `webhook_secret` is used to authenticate an inbound GitHub webhook based on `repository.owner.login` (or `organization.login`), but the downstream handlers (e.g. `PushHandler`) resolve which `Stack`/`Repository` to act on using the unrelated `repository.full_name` field from the same JSON body. When an organization is configured without a `webhook_secret` (an explicitly supported, documented configuration — see `config/secrets.development.shopify.yml` and `docs/setup.md`), `GitHubApp#verify_webhook_signature` unconditionally returns `true`, so the signature check is a no-op for that organization while still granting the forged payload full authority to target any repository/stack in the installation via `full_name`.

### Finding Description
`verify_signature` computes the authenticating organization from the payload itself: [2](#0-1) [3](#0-2) 

`GitHubApp#verify_webhook_signature` bypasses verification entirely when no secret is configured for that organization: [4](#0-3) 

This is a supported deployment state, not a misconfiguration: the setup docs and shipped config templates explicitly show `webhook_secret:` left blank/nil, and the "Using Multiple Github Applications" section documents per-organization secrets, implying some orgs may reasonably be left without one (e.g., internal testing orgs, or orgs onboarded before enabling the feature).

Once past `verify_signature`, the raw JSON `params` are dispatched to handlers, none of which re-validate that `repository.full_name`'s owner matches the `repository.owner.login`/`organization.login` used for authentication. `Handler#repository_name`/`#stacks` and `PushHandler#process` resolve the affected `Stack` purely from `repository.full_name`: [5](#0-4) [1](#0-0) 

This is the same class of bug as the reported `withdrawETH()` issue: an operation (`stacks`/`process`) acts on a field (`repository.full_name`) that is never covered by the authentication check, which is instead bound to a different, uncorrelated field (`repository.owner.login`/`organization.login`).

### Impact Explanation
An unauthenticated remote attacker who knows (or guesses) the name of any organization configured in `Shipit.github` config without a `webhook_secret` can POST a crafted `push` event to `/webhooks` with `repository.owner.login` set to that unprotected org, but `repository.full_name` set to `"victim-org/protected-repo"`. `verify_signature` will pass (secret-less org → `true`), and `PushHandler` will locate the real `Stack` for `victim-org/protected-repo` and call `sync_github`, enqueuing `GithubSyncJob` with an attacker-chosen `expected_head_sha`. This can drive `Commit#schedule_continuous_delivery` and `Stack#trigger_continuous_delivery`, causing an **unauthorized deploy** for a stack belonging to an organization that is otherwise properly protected by its own webhook secret — meeting the "unauthorized deploy" Critical-impact criterion. The same technique also allows forging `status`, `check_suite`, and `membership` events against any repository/stack, e.g. injecting fake commit statuses that satisfy CI requirements and unblock deploys/merges.

### Likelihood Explanation
Requires: (1) at least one organization in the Shipit installation configured without a `webhook_secret` — an explicitly documented, non-exotic configuration; (2) knowledge of that organization's login name, which is discoverable (organization names are public on GitHub, and Shipit's own UI/URLs expose stack `owner/name`). No GitHub App private key, session, `ApiClient` token, or repository write access is needed — only the ability to send an unauthenticated HTTP POST to the public `/webhooks` endpoint. This is a realistic, low-effort attack path for any multi-organization Shipit deployment where secret configuration is inconsistent across organizations.

### Recommendation
Bind the authenticating organization to every field the handlers subsequently trust: after computing `repository_owner`, verify that it matches the owner segment of `repository.full_name` (and `organization.login` if present) before dispatching to handlers. Additionally, treat a missing `webhook_secret` as a hard configuration error (reject the webhook, or refuse to boot) rather than silently bypassing signature verification, since `verify_webhook_signature`'s `return true unless webhook_secret` degrades a defense-in-depth control into a full bypass.

### Proof of Concept
1. Configure Shipit with two organizations: `openorg` (no `webhook_secret` set, as shown in `config/secrets.development.shopify.yml`) and `secureorg` (has a `webhook_secret`, and owns a stack `secureorg/prod-app` with `continuous_deployment: true`).
2. As an anonymous attacker, POST to `/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha-or-existing-sha>",
  "repository": { "owner": { "login": "openorg" }, "full_name": "secureorg/prod-app" }
}
```
No `X-Hub-Signature` header (or any arbitrary value) is required.
3. `verify_signature` resolves `repository_owner = "openorg"`, fetches `Shipit.github(organization: "openorg")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` unconditionally (`lib/shipit/github_app.rb:76-77`).
4. `PushHandler#process` resolves `stacks` via `Repository.from_github_repo_name("secureorg/prod-app")` and calls `stack.sync_github`, enqueuing `GithubSyncJob` for the `secureorg` stack — despite the request never being validated against `secureorg`'s own webhook secret.

### Citations

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```
