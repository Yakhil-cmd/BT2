### Title
Webhook signature is verified against the wrong organization key while handlers act on an unrelated `repository.full_name` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
The `WebhooksController#verify_signature` selects which organization's webhook secret to check the HMAC signature against by reading an **attacker-controlled** field from the *unverified* JSON body (`repository.owner.login`, falling back to `organization.login`). The event handlers that subsequently act on the payload (writing statuses, syncing commits, creating pull requests, etc.) instead key off a *different* field of the same payload — `repository.full_name` — via `Handler#repository_name`/`Handler#stacks`. Nothing binds the organization whose secret validated the signature to the repository that the handler actually mutates.

### Finding Description
`verify_signature` computes the signing organization purely from payload content: [1](#0-0) [2](#0-1) 

```
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```

`Shipit.github(organization: repository_owner)` returns a `GithubApp`/`GithubOrganizationApp` configured for that organization, and `verify_webhook_signature` is: [3](#0-2) 

```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
```

Critically, if the organization resolved from the attacker-supplied `repository.owner.login`/`organization.login` field has **no `webhook_secret` configured** (`@webhook_secret = @config[:webhook_secret].presence`, initialized in `GithubApp#initialize`), `verify_webhook_signature` returns `true` unconditionally — no HMAC is checked at all, and no secret needs to be known by the attacker.

Once the request passes `verify_signature`, `WebhooksController#create` dispatches the *entire* raw JSON body to the registered handler(s) unchanged: [4](#0-3) 

Handlers such as `PushHandler` and `StatusHandler` locate the target `Stack`/`Commit` records using a *different* field of the same body — `repository.full_name` — via the base `Handler` class: [5](#0-4) 

```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [6](#0-5) [7](#0-6) 

There is no check anywhere that `repository.full_name`'s owner matches the `repository.owner.login`/`organization.login` used to pick the verification secret. An attacker can therefore craft a payload where:
- `repository.owner.login` = an organization that is *known* to Shipit (so `GithubOrganizationUnknown` isn't raised) but has **no webhook secret configured** — causing `verify_webhook_signature` to short-circuit to `true`.
- `repository.full_name` = `<victim-org>/<victim-repo>` — any repository that already has a `Stack` configured in this Shipit instance, regardless of organization.

The request then reaches `PushHandler`, which calls `stack.sync_github(expected_head_sha: params.after)` for the victim stack — enqueuing a `GithubSyncJob` that fetches from GitHub using the victim's SHA claim — or `StatusHandler`, which directly writes a commit status (`create_status_from_github!`) for any commit SHA the attacker names, with attacker-chosen `state`, `description`, `target_url`, `context`. This is the exact analog of the reported bug class: a value used to satisfy a policy/verification gate (`repository.owner.login`/`organization.login` → signature check) is decoupled from the value that the rest of the logic actually trusts to act (`repository.full_name` → which `Stack`/`Commit` gets mutated).

### Impact Explanation
This crosses the "an organization that authenticated versus the repository that is written" trust boundary explicitly called out in scope. An unauthenticated external attacker (anyone who can POST to the public `/webhooks` endpoint) can:
- Forge arbitrary commit statuses (`StatusHandler`) on any tracked commit, which can flip `Commit#deployable?`/CI gating (`ci.require`) and enable an **unauthorized deploy** of a commit that never actually passed CI, satisfying the "unauthorized deploy" Critical/High impact criterion.
- Force `PushHandler`/`sync_github` to run for arbitrary stacks with attacker-chosen `expected_head_sha`, which can desynchronize the tracked branch state.

This requires no `ApiClient` token, no `webhook_secret`, no GitHub App private key, and no repository write access — only that at least one organization configured in the Shipit instance lacks a `webhook_secret` (a documented-as-optional field in `docs/setup.md`, `github.webhook_secret` "If you've set a webhook secret during the App creation, you should copy it here" — implying it may legitimately be left unset for some installs).

### Likelihood Explanation
Likelihood is contingent on at least one configured organization having no `webhook_secret` set, which the setup docs treat as optional/best-effort rather than mandatory. In multi-organization Shipit deployments (the `repository_owner` lookup and `Shipit::GithubHook::Organization` model exist specifically to support multiple orgs), it's plausible that some smaller or newly-added organization is configured without a webhook secret while a security-sensitive stack belongs to another, properly-secured organization. No credentials, no timing races, and no privileged access are required to exploit it once that precondition holds — it's a single crafted HTTP POST.

### Recommendation
- Require `webhook_secret` to be present for every configured organization/app; refuse (422) webhook processing rather than defaulting to `verified = true` when `webhook_secret` is blank in `GithubApp#verify_webhook_signature`.
- Cross-validate that the resolved `repository_owner` used for signature verification matches the owner encoded in `repository.full_name` before dispatching to handlers, e.g. in `WebhooksController#verify_signature` or `Handler#repository_name`.
- Consider verifying signatures against a single, installation-wide secret rather than one resolved from attacker-controlled JSON, if the deployment model allows it.

### Proof of Concept
1. Configure Shipit with two orgs: `secure-org` (has `webhook_secret` set) and `open-org` (no `webhook_secret` configured), each recognized by `Shipit.github(organization: ...)`.
2. Ensure a `Stack`/`Repository` exists for `secure-org/critical-app` with a tracked `Commit` (sha `deadbeef`).
3. POST to `/webhooks` with header `X-Github-Event: status` and body:
```json
{
  "repository": { "owner": { "login": "open-org" }, "full_name": "secure-org/critical-app" },
  "sha": "deadbeef",
  "state": "success",
  "context": "ci/forged"
}
```
No `X-Hub-Signature` header, or any arbitrary value, is required — `repository_owner` resolves to `open-org`, `Shipit.github(organization: 'open-org').verify_webhook_signature` returns `true` because `open-org`'s `webhook_secret` is blank, `verify_signature` passes, and `StatusHandler` creates a forged successful status on `secure-org/critical-app`'s commit `deadbeef`, potentially unblocking a deploy that should be CI-gated.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
