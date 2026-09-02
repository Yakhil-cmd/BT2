This confirms the key finding. `WebhooksController#verify_signature` selects the GitHub App/webhook secret using `repository_owner`, which is parsed as `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` (`app/controllers/shipit/webhooks_controller.rb:25-30,59-62`). But the actual event handler that mutates state (`PushHandler`, etc.) looks up the target `Repository`/`Stack` using an entirely different, independently attacker-controlled payload field: `payload.dig('repository', 'full_name')` (`app/models/shipit/webhooks/handlers/handler.rb:33-38`). Nothing in the codebase enforces that `repository.owner.login` and the owner portion of `repository.full_name` are the same string. [1](#0-0) ### Title
Webhook signature verified against the org named in `repository.owner.login` while the mutated repository is looked up from the unrelated `repository.full_name` field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` HMAC-verifies the raw request body against the webhook secret of the GitHub App configuration selected by `repository_owner`, a value parsed straight out of the attacker-supplied JSON body (`params.dig('repository', 'owner', 'login')`). Every downstream event `Handler` (e.g. `PushHandler`) then looks up the `Repository`/`Stack` to mutate using `payload.dig('repository', 'full_name')` — a second, independent string field from the same JSON body. Nothing binds these two fields together, so the signature is validated against one organization's secret while the write targets whatever repository the `full_name` field names.

### Finding Description
- `WebhooksController#verify_signature` computes `repository_owner` from the payload itself and uses it purely to pick *which* configured GitHub App's `webhook_secret` to check the HMAC against: [1](#0-0) [2](#0-1) 

- Shipit supports multiple GitHub App configurations keyed by organization name (`lib/shipit.rb` `github_app_config`), and `GitHubApp#verify_webhook_signature` explicitly treats a missing `webhook_secret` as automatically valid: [3](#0-2) 

- The event handlers never re-check `repository.owner.login`. They resolve the actual `Repository`/`Stack` to act on from a *different* payload field, `repository.full_name`: [4](#0-3) [5](#0-4) [6](#0-5) 

This is structurally identical to the analog bug class: an equality the code implicitly assumes — "the organization whose secret authenticated this request" == "the organization owning the repository being written" — is never actually checked. The verified field (`repository.owner.login`, used only to pick the HMAC secret) and the acted-upon field (`repository.full_name`, used to find the `Repository`/`Stack` and enqueue jobs like `GithubSyncJob`) are two separate JSON leaves with no cross-validation, exactly mirroring the CelerIM bug where the field used to select the "trusted" branch (token name) diverged from the field actually acted upon (`sendingAssetId`/`canonical()` result).

### Impact Explanation
If a Shipit deployment configures multiple GitHub organizations (a documented, supported configuration — see `docs/setup.md` "Using Multiple Github Applications" and `config/secrets.development.shopify.yml`), and any one of those organizations has no `webhook_secret` set (also a documented/supported state — `webhook_secret: # nil` in the sample config, and `verify_webhook_signature` explicitly returns `true` when `webhook_secret` is blank), an unprivileged external attacker can:
1. Craft a webhook POST to `/webhooks` with `X-Github-Event: push`.
2. Set `repository.owner.login` to the organization that has no (or a weak/leaked) webhook secret, so `verify_signature` passes trivially.
3. Set `repository.full_name` to `victim-org/victim-repo` — a completely different, unrelated organization/repository that Shipit also manages.

This causes the `PushHandler` (or `check_suite`, `status`, `pull_request`, `membership` handlers — all of which use the same `repository_name`/`full_name` resolution in `Handler#stacks`) to act on the victim stack, e.g. triggering `stack.sync_github(expected_head_sha: params.after)`, which can enqueue `GithubSyncJob` and influence undeployed-commit tracking and downstream continuous-deployment triggers for a repository the attacker never had signature-verified access to. This is an authentication-bypass class issue: signature verification is satisfied against the wrong trust boundary, letting an unauthenticated party inject validated-looking events that affect an unrelated repository's Shipit state.

### Likelihood Explanation
Requires: (a) a multi-org Shipit deployment, and (b) at least one configured org with no/blank/weak webhook secret — both are first-class, documented configurations in this engine (not a misuse), making the precondition realistic rather than exotic. No credentials, tokens, or repository write access are needed; the attacker only needs to know the Shipit webhook endpoint is shared across orgs and that one org lacks a secret.

### Recommendation
Bind the two fields together instead of treating them independently: after computing `repository_owner` and verifying the signature, re-derive the acted-upon organization from `repository.full_name` (or `organization.login`) inside `WebhooksController`/`Handler` and reject the request (422) if it doesn't match the organization whose secret validated the signature. Alternatively, always require every configured GitHub App to have a non-blank `webhook_secret` (remove the `return true unless webhook_secret` shortcut in `GitHubApp#verify_webhook_signature`), and additionally assert `payload.dig('repository','full_name').split('/').first == repository_owner` before dispatching to handlers.

### Proof of Concept
1. Deploy Shipit with two orgs configured under `secrets.github`: `trusted-org` (has stacks the attacker wants to affect) and `attacker-org` (configured with `webhook_secret: nil`, as shown as a valid template in `config/secrets.development.shopify.yml`).
2. POST to `/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/main",
  "after": "deadbeef",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "trusted-org/victim-repo"
  }
}
```
No `X-Hub-Signature` header, or any arbitrary value, is required.
3. `verify_signature` resolves `Shipit.github(organization: "attacker-org")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` unconditionally — the request passes.
4. `PushHandler#process` resolves `Repository.from_github_repo_name("trusted-org/victim-repo")` via `repository_name` (`payload.dig('repository','full_name')`) and calls `stack.sync_github(...)` on the victim's stack, with no verification ever performed against `trusted-org`'s actual webhook secret.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
