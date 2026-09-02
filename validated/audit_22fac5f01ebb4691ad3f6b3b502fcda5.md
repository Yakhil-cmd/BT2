### Title
Webhook signature is verified against `repository.owner.login`, but handlers act on the unverified `repository.full_name` / global commit sha - cross-organization webhook forgery - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary

### Finding Description
`WebhooksController#verify_signature` selects the `GithubApp` (and thus the HMAC `webhook_secret`) used to validate the signature by reading `repository_owner`, which is taken from `params.dig('repository', 'owner', 'login')` (falling back to `params.dig('organization', 'login')`): [1](#0-0) [2](#0-1) 

Once the signature is accepted, the request body is dispatched unchanged to the event handlers (`Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }`): [3](#0-2) 

Every handler that resolves the target `Repository`/`Stack` (`PushHandler`, `CheckSuiteHandler`) does so through `Handler#stacks`, which reads a *different* field of the same JSON body — `repository.full_name` — not `repository.owner.login`: [4](#0-3) 

`StatusHandler` doesn't even scope by repository at all — it matches any `Commit` in the whole database by `sha`: [5](#0-4) 

Shipit explicitly supports hosting several independent GitHub Apps (one per organization) on a single instance, each with its own `webhook_secret`, configured under distinct top-level keys in `secrets.yml`: [6](#0-5) 

This creates the binding mismatch: `repository_owner` (the field cryptographically bound to the accepted signature) ≠ `repository.full_name` / the target `Commit.sha` (the fields actually acted upon by the handlers). The controller proves "this payload was signed by organization X's app secret," but the handlers trust the payload to also assert "and this event concerns repository Y," a claim that is never covered by that same signature.

### Impact Explanation
An attacker who legitimately owns and administers one of the several organizations configured in this Shipit instance (a normal, unprivileged relationship — they know their own app's `webhook_secret` because they configured it themselves when installing their GitHub App, exactly as documented in `docs/setup.md`) can:

1. Compute a valid `X-Hub-Signature` using their own org's `webhook_secret`.
2. Set `repository.owner.login` (or `organization.login`) to their own org, so `verify_signature` selects their own app/secret and passes.
3. Set `repository.full_name` (push/check_suite) or `sha` (status) to point at a repository/commit belonging to an *unrelated organization* also tracked by the same Shipit instance.

This lets the attacker:
- Force a `sync_github` for another organization's stack (`PushHandler`), or
- Forge a `commit_status` (`StatusHandler`) for **any commit in any stack across the whole Shipit instance**, regardless of organization, since the lookup is unscoped by repository.

Since deploy safety in Shipit is gated on commit `deployable?`/CI-status checks, forging a "success" status on a commit that actually failed CI (or was never checked) can make an otherwise-blocked commit appear deployable, enabling an unauthorized deploy of a cross-organization repository the attacker does not own — matching the "Critical: … unauthorized deploy" and "cross-repository writes" impact categories.

### Likelihood Explanation
This requires no session, `ApiClient` token, or stolen secret — only a self-provisioned GitHub App/webhook secret for one organization hosted on the shared Shipit instance, which is the documented, supported multi-tenant configuration (`docs/setup.md` "Using Multiple Github Applications"). The `/webhooks` endpoint is unauthenticated by design (it only checks HMAC), and is reachable by anyone able to craft an HTTP POST with the correct header/body pairing. Likelihood is therefore realistic in any multi-org Shipit deployment.

### Recommendation
Bind the field used for signature-key selection to the field used for repository resolution: after selecting the app via `repository_owner`, re-validate that `repository.full_name`'s owner segment equals `repository_owner` (and reject otherwise), or scope `StatusHandler`'s/`Handler#stacks` lookups by the same verified organization instead of trusting `full_name`/`sha` in isolation.

### Proof of Concept
1. Shipit is configured (per `docs/setup.md`) with two GitHub Apps: `org-attacker` (attacker is the GitHub org owner and set its `webhook_secret` themselves) and `org-victim` (unrelated, tracked in the same Shipit instance).
2. Attacker builds a `status` webhook JSON body:
```json
{
  "sha": "<victim commit sha that is currently failing CI>",
  "state": "success",
  "repository": {"owner": {"login": "org-attacker"}, "full_name": "org-attacker/whatever"}
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC(org-attacker webhook_secret, body)`.
4. POST to `/webhooks` with `X-Github-Event: status`.
5. `WebhooksController#verify_signature` resolves `Shipit.github(organization: "org-attacker")` and successfully verifies the signature (attacker's own valid secret).
6. `StatusHandler#process` runs `Commit.where(sha: params.sha)` — matching the victim's commit regardless of the signed organization — and creates a forged "success" status on it, per [5](#0-4) , potentially unblocking a deploy that should have been gated on CI.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** docs/setup.md (L182-209)
```markdown
### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

```yml
production:
  github:
    somegithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
    someothergithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
```
```
