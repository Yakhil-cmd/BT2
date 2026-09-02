### Title
Webhook Signature Verification Selects Org By `repository.owner.login` While Handlers Act On `repository.full_name`, Enabling Cross-Organization Writes - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which `webhook_secret` to validate the inbound signature against using the untrusted, unverified payload field `repository.owner.login` (falling back to `organization.login`), while the handlers that actually mutate application state select the target `Stack`/`Repository` using a *different* field of the same payload, `repository.full_name`. On a Shipit instance configured for multiple GitHub organizations, an org that legitimately controls its own GitHub App installation (and thus its own valid `webhook_secret`) can craft a signed webhook whose `owner.login` matches its own org (so signature verification passes) but whose `full_name` points at a stack belonging to a different, victim organization hosted on the same Shipit instance. This is the same class of bug as the reported oracle issue: one field is used to establish trust/identity while a different, independently attacker-controlled field is later used to determine what gets written.

### Finding Description
`verify_signature` computes the verifying identity purely from payload content that has not yet been authenticated:

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [1](#0-0) [2](#0-1) 

Once the signature check passes for whichever organization `repository_owner` names, the full unmodified `params` is dispatched to event handlers:

```ruby
def create
  params = JSON.parse(request.raw_post)
  Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }
  head(:ok)
end
``` [3](#0-2) 

Handlers, however, resolve the actual `Stack`/`Repository` to mutate from a *different* field, `repository.full_name`:

```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [4](#0-3) 

Because the HMAC signature only proves the payload was signed with *some* configured `webhook_secret`, and the secret used for verification is chosen from `repository.owner.login`/`organization.login` while the object written is chosen from `repository.full_name`, these two fields are never cross-checked against each other. An org that owns its own legitimate GitHub App installation on the same Shipit instance (a normal, supported multi-tenant configuration, e.g. `somegithuborg` / `someothergithuborg` in `config/secrets.development.shopify.yml`) knows its own valid `webhook_secret` and can sign a payload where:
- `repository.owner.login` (and/or top-level `organization.login`) = the attacker's own org — so `Shipit.github(organization: repository_owner).verify_webhook_signature` succeeds using the attacker's own secret.
- `repository.full_name` = `victim-org/victim-repo` — a stack belonging to a completely different tenant.

This equality that should hold but is broken:
`organization whose secret authenticated the request == organization that owns the repository being written to`

### Impact Explanation
The consequence is unauthorized cross-repository writes on a shared Shipit deployment: the `push` handler enqueues `GithubSyncJob` for the resolved stack based on `full_name`, and the `status`/`check_suite`/`pull_request` handlers likewise resolve their target stacks the same way, meaning they can create commit `Status` records, trigger check-run refreshes, or affect pull-request/merge-queue state for a victim organization's stacks without that organization's participation. This matches the Critical severity criterion "cross-repository writes."

### Likelihood Explanation
This requires only that the Shipit instance host more than one GitHub organization (a documented, supported configuration) and that the attacker controls one of those organizations (and thus its own webhook secret) — no access to the victim's secrets, GitHub App private key, or a Shipit session/API token is needed. This is a realistic configuration for shared internal deployment tooling.

### Recommendation
Verify that the organization used to select the signing secret is the same organization that owns the repository the handlers will act upon — i.e., derive both from the same trusted field (or explicitly assert `repository.full_name`'s owner segment matches `repository_owner`) before dispatching to handlers, rejecting the request otherwise.

### Proof of Concept
1. Attacker registers/administers `attacker-org` as one of the configured GitHub orgs on the shared Shipit instance and knows `attacker-org`'s `webhook_secret` (their own legitimate GitHub App installation secret).
2. Attacker crafts a `push` event payload:
```json
{
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" },
  "after": "<attacker-chosen sha>"
}
```
3. Attacker signs the raw JSON body with HMAC-SHA1 using `attacker-org`'s `webhook_secret` and sends it as `X-Hub-Signature` to `POST /github/webhooks` (or equivalent mounted path) with `X-Github-Event: push`.
4. `verify_signature` resolves `repository_owner` = `attacker-org`, fetches `Shipit.github(organization: 'attacker-org')`, and the signature check succeeds because it was signed with the correct secret for that org.
5. `create` passes the full payload to `Shipit::Webhooks.for_event('push')` handlers, which resolve the target via `payload.dig('repository', 'full_name')` = `victim-org/victim-repo`, enqueuing `GithubSyncJob` (and other side effects) against the victim's stack — despite the attacker never having proven any relationship to `victim-org`.

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
