### Title
Webhook signature is verified against the organization derived from `repository.owner.login`, but events act on the (unbound) `repository.full_name` field, allowing cross-organization stack write - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/`webhook_secret` to validate the HMAC signature against using `repository_owner`, which is read from `params.dig('repository', 'owner', 'login')` (falling back to `params.dig('organization', 'login')`). However, none of the webhook handlers use that same field to decide which `Stack`/`Repository` the event applies to — they instead resolve the target repository from a *different*, independently attacker-controlled field: `payload.dig('repository', 'full_name')`. In a multi-organization Shipit deployment (explicitly supported, see `config/secrets.development.shopify.yml`, which configures multiple orgs each with its own `webhook_secret`), these two fields are never checked for consistency, breaking the binding "organization whose secret authenticated the request" == "repository the event is applied to."

### Finding Description
`verify_signature` in `app/controllers/shipit/webhooks_controller.rb` does: [1](#0-0) 
selecting `Shipit.github(organization: repository_owner)` and verifying the HMAC over the *entire* raw body against that organization's `webhook_secret`: [2](#0-1) 

`repository_owner` is taken from `repository.owner.login` (or `organization.login`) inside the same JSON body that the attacker fully controls before signing it with their own org's secret.

Every event handler, however, resolves the actual `Stack`/`Repository` to act on using a completely separate field, `repository.full_name`, in `Handler#stacks` / `Handler#repository_name`: [3](#0-2) 

Nothing enforces that `repository.full_name`'s owner segment matches `repository.owner.login`. An attacker who administers their own GitHub organization (`attacker-org`) that is legitimately onboarded to this Shipit instance (a normal, unprivileged-relative-to-other-orgs tenant, as this engine explicitly supports multiple `github:` orgs each with a distinct `webhook_secret`, per `config/secrets.development.shopify.yml`) knows `attacker-org`'s own `webhook_secret`. They can craft a payload where:
- `repository.owner.login` = `"attacker-org"` (so `verify_signature` selects and successfully verifies against the secret they know)
- `repository.full_name` = `"victim-org/victim-repo"` (so the handler resolves and acts on the victim's stack)

Since the HMAC is only checked for validity against *some* configured org's secret — the org named inside the same forgeable payload — and the acted-upon repository is a different, unchecked field, the signature does not actually bind "which repository this event is authorized for." This equality is broken: `organization whose webhook_secret authenticated the payload` ≠ `repository that handlers write to`.

### Impact Explanation
Using `PushHandler` (`app/models/shipit/webhooks/handlers/push_handler.rb:12-17`), the attacker can trigger `stack.sync_github(expected_head_sha: ...)` on any tracked victim stack across organizations, forcing a specific SHA to be treated as the head of a branch. Combined with `continuous_deployment` stacks (`Stack.schedule_continuous_delivery`, `app/models/shipit/stack.rb:129-133`), this can result in an **unauthorized deploy** of attacker-chosen commits on a victim repository the attacker has no legitimate access to — meeting the Critical bar ("unauthorized deploy"). `CheckSuiteHandler` and `StatusHandler` similarly let the attacker inject fabricated CI/check-run statuses (`Commit#create_status_from_github!`) for arbitrary victim commits, which can be used to force a commit to appear "deployable" and bypass CI gating for a deploy.

### Likelihood Explanation
This requires the deployer to run a multi-organization Shipit instance (explicitly documented/supported configuration pattern with a `github:` hash keyed by org, each with independent `webhook_secret`s) and for the attacker to control at least one onboarded organization/app installation with a known `webhook_secret` — a realistic scenario for any shared/multi-tenant Shipit deployment serving several GitHub orgs, and requires no privileged Shipit credentials (no `ApiClient` token, no session, no GitHub App private key) — only the ability to send an arbitrary POST to the public `/webhooks` endpoint with a signature computed from a secret the attacker legitimately possesses for their own org.

### Recommendation
Bind the field used to select/verify the signing secret to the field used to resolve the target repository: derive the organization to check against from `repository.full_name`'s owner segment (or otherwise verify `repository.owner.login` == `full_name.split('/').first`) before dispatching to handlers, and reject the request if they diverge.

### Proof of Concept
1. Onboard/control `attacker-org` in a multi-org Shipit deployment (known `webhook_secret`).
2. Send `POST /webhooks` with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker chosen sha already present as a Commit on victim stack>",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
3. Sign the raw body with `attacker-org`'s known `webhook_secret` (`sha1=` HMAC as computed in `GithubApp#verify_webhook_signature`, `lib/shipit/github_app.rb:76-83`) and set it as `X-Hub-Signature`.
4. `verify_signature` selects `attacker-org`'s config via `repository_owner` = `"attacker-org"` and successfully verifies the signature.
5. `PushHandler#process` resolves `stacks` via `full_name` = `"victim-org/victim-repo"` and calls `stack.sync_github(expected_head_sha: ...)` on the victim's stack, which can trigger continuous deployment of the attacker-chosen commit.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```
