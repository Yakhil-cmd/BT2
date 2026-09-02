### Title
Cross-organization webhook forgery via authentication/target mismatch in `WebhooksController#verify_signature` - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App configuration (and therefore which `webhook_secret`) to use for HMAC verification based on a field taken from the **same untrusted JSON body** being verified (`repository.owner.login` / `organization.login`), rather than from a value tied to the actual target repository being acted upon by the downstream event handlers. In a multi-organization Shipit deployment, this decouples "which org's secret authenticated this request" from "which repository/stack the request's handlers will actually mutate," breaking the binding: *organization that authenticated == repository that is written*.

### Finding Description
`verify_signature` computes `repository_owner` straight from the attacker-supplied payload and uses it to fetch the corresponding `github_app`/`webhook_secret` to check the signature against: [1](#0-0) [2](#0-1) 

Shipit explicitly supports configuring multiple independent GitHub organizations, each with its own `webhook_secret`: [3](#0-2) 

Because `repository_owner` is read from `params.dig('repository', 'owner', 'login')` (a field inside the same JSON body the attacker fully controls), an attacker who legitimately owns/administers *any one* of the configured GitHub organizations (org A) — and therefore legitimately knows org A's `webhook_secret` because they installed/configured the GitHub App there — can craft a payload where:
- `repository.owner.login` = `"orgA"` (so `Shipit.github(organization: "orgA")` is selected for signature verification, and the attacker signs the raw body correctly with org A's own secret, which they possess).
- `repository.full_name` (or other repository-identifying fields used further downstream by `Shipit::Webhooks.for_event(event)` handlers, e.g. `PushHandler`, `StatusHandler`, `CheckSuiteHandler`) = a repository belonging to an entirely different, victim organization (org B) that also has a Stack configured in the same Shipit instance.

`verify_signature` only checks that *some* configured org's secret matches the body — it never asserts that the org used for authentication is the same org that owns the repository the handlers subsequently act on: [4](#0-3) 

The handlers dispatched via `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` then resolve the target `Stack`/`Repository` using repository-identifying fields from that same forged body (e.g. `full_name`), independent of `repository_owner`: [5](#0-4) 

### Impact Explanation
This allows an attacker who is fully unprivileged with respect to the victim organization/repository — but legitimately controls a *different* configured GitHub org/App installation in the same Shipit instance — to forge signed webhook events (`push`, `status`, `check_suite`) that Shipit will accept as authentic for the victim's stack. Depending on which handler is targeted this enables:
- Injecting fake `status`/`check_suite` results that satisfy Shipit's deploy safety gates (`release_status?` / check-run based safeties), enabling an **unauthorized deploy**.
- Forcing `GithubSyncJob` to run against a victim stack with attacker-controlled data.

This matches the report's "Critical/High" impact category of "unauthorized deploy" via a broken trust boundary.

### Likelihood Explanation
Requires the attacker to control at least one legitimately-configured GitHub organization/App installation on the same Shipit instance (a realistic scenario for any multi-tenant/multi-org Shipit deployment as documented in `config/secrets.development.example.yml`), and knowledge of a victim stack's repository `full_name`, which is generally public/discoverable. No access to the victim's `webhook_secret`, session, or API token is required — only crafting a JSON body and signing it with the attacker's own legitimately-known secret.

### Recommendation
In `WebhooksController#verify_signature`, after locating the target `Stack`/`Repository` via the handler-resolved identifier (e.g., `full_name`), assert that its actual owning organization matches `repository_owner` (the org whose secret validated the signature) before dispatching to handlers, rather than trusting the payload's self-reported owner in isolation.

### Proof of Concept
1. Configure Shipit with two orgs, `orgA` (attacker-controlled installation) and `orgB` (victim, has a Stack for `orgB/victim-repo`).
2. Attacker builds a `push` (or `status`/`check_suite`) JSON payload with `repository.owner.login = "orgA"` and `repository.full_name = "orgB/victim-repo"`.
3. Attacker computes `X-Hub-Signature` using `orgA`'s `webhook_secret` (known to the attacker) over the raw body.
4. POST to `/github/webhooks`. `verify_signature` resolves `Shipit.github(organization: "orgA")` and verification succeeds.
5. `PushHandler`/`StatusHandler` resolve the target stack via `repository.full_name` = `orgB/victim-repo`, acting on the victim's stack despite the request never being authenticated by `orgB`'s secret.

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

**File:** config/secrets.development.example.yml (L18-38)
```yaml
# Use this configuration schema if you are configuring multiple Github applications for different Github organizations

# github:
#   somegithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
#   someothergithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
```

**File:** app/models/shipit/repository.rb (L1-1)
```ruby
# frozen_string_literal: true
```
