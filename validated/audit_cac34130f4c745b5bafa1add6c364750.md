### Title
Webhook signature is verified against the organization named in `repository.owner.login`, but handlers act on the (unverified-against-that-binding) `repository.full_name` field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which organization's `webhook_secret` to use for HMAC verification based on `repository.owner.login` (or `organization.login`) taken straight from the untrusted JSON body, then verifies the raw body against that org's secret. Once verification passes, every downstream handler re-reads the same untrusted body and identifies the *repository to act on* from `repository.full_name`, a separate field of the same attacker-controlled payload, without re-deriving it from, or cross-checking it against, the value that was actually used to select the signing secret.

### Finding Description
`verify_signature` picks the `GitHubApp` (and therefore the `webhook_secret`) to check the signature against like this: [1](#0-0) [2](#0-1) 

`repository_owner` is read straight out of the JSON body (`params.dig('repository', 'owner', 'login')`). Verification only proves that the HMAC of the raw body matches the secret configured for *that org name*.

Once `head(422)` is not triggered, `create` dispatches the same raw payload to handlers: [3](#0-2) 

Handlers determine which `Stack`/`Repository` to mutate from a *different* field of the same payload: [4](#0-3) 

`Shipit.github(organization: ...)` supports per-organization configuration with distinct `webhook_secret`s (documented in `config/secrets.development.example.yml`), meaning different orgs can have different signing secrets: [5](#0-4) 

Because `verify_signature` binds the signature to `repository.owner.login` while `Handler#repository_name` binds the mutated resource to `repository.full_name`, an attacker who legitimately knows (or controls) the `webhook_secret` of *one* configured organization (e.g. because they administer that org's GitHub App) can HMAC-sign a forged payload with `repository.owner.login` set to their own org (so the check passes) while setting `repository.full_name` to `"other-org/other-repo"`. The signature check never inspects `full_name`, so the two identities are never bound together. Handlers such as `PushHandler`/`StatusHandler` will then act on the victim organization's repository/stack (e.g. `stacks.each { |stack| ... }` scheduling `GithubSyncJob`, updating commit statuses, triggering merges) using data forged by an attacker who was never authenticated for that organization.

This is the same class of defect as the `QuantAMMBaseAdministration::onlyExecutor` bug: a check verifies possession of a credential/role tied to one identity (`repository.owner.login` / `EXECUTOR_ROLE` holder), but the privileged action is actually performed against a different, uncoupled target (`repository.full_name` / arbitrary `TimelockController` calldata) that was never covered by that same verification.

### Impact Explanation
This breaks the equality that should hold: `organization whose secret signed the request == organization/repository being written to`. In a multi-organization Shipit deployment (the officially supported "multiple Github applications" configuration), a party who is entitled to send webhooks for org A can forge push/status/check_suite events that get applied to org B's stacks — causing cross-repository writes: bogus commit statuses, forced `GithubSyncJob` runs, and (via status/check_suite driven CI gating) potentially unblocking or influencing deploys/merges on repositories the attacker does not control. This satisfies the "Critical: cross-repository writes / unauthorized deploy" bar, without requiring any Shipit session, `ApiClient` token, or GitHub App private key — only knowledge of one org's `webhook_secret`, which by design many external, less-trusted parties (app owners of a single org) may hold.

### Likelihood Explanation
Exploitability requires: (1) the deployment to be configured with the documented multi-organization `github:` secrets block (each org having its own `webhook_secret`), and (2) the attacker to know one such org's `webhook_secret`. This is a realistic scenario for shared/hosted Shipit instances serving multiple GitHub organizations with different trust levels, where a single organization's webhook secret is not meant to authorize actions on other organizations' repositories.

### Recommendation
Bind the verified identity to the acted-upon identity: after selecting `github_app` via `repository_owner`, re-derive/require that the org name embedded in `repository.full_name` (and any other repository/org fields consumed by handlers) matches `repository_owner` before dispatching to handlers, or reject payloads where these fields disagree. Alternatively, verify signatures using a single canonical field and have handlers consume that exact same field rather than re-parsing the payload independently.

### Proof of Concept
1. Deployment configures two orgs, `orgA` (attacker-known secret `Sa`) and `orgB` (victim, secret `Sb`, unknown to attacker).
2. Attacker crafts a `push` webhook JSON body:
```json
{
  "repository": { "owner": { "login": "orgA" }, "full_name": "orgB/victim-repo" },
  "after": "<attacker-chosen-sha>"
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC(Sa, raw_body)` and POSTs to `/webhooks`.
4. `verify_signature` calls `Shipit.github(organization: "orgA")` and successfully verifies the signature against `Sa`.
5. `Shipit::Webhooks.for_event('push')` handlers run `Handler#stacks`, which resolves `Repository.from_github_repo_name("orgB/victim-repo")` and dispatches `GithubSyncJob`/status updates against `orgB`'s stack — despite the request never being authenticated for `orgB`.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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
