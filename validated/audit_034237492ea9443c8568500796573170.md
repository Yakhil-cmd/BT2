### Title
Webhook signature verification keys off `repository.owner.login`/`organization.login` while event handlers act on the independently-controlled `repository.full_name` field, letting a webhook forged for one configured GitHub organization write into any stack in the Shipit instance - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which `GitHubApp` (and thus which `webhook_secret`) to verify a webhook against solely from `repository.owner.login`/`organization.login` in the JSON body. `Shipit::Webhooks::Handlers::Handler#stacks`/`repository_name` and other handlers (e.g. `StatusHandler`) instead resolve the actual write target from a different field of the same payload (`repository.full_name`, or even just a bare `sha`), which is not tied to the organization used for signature selection. In a multi-organization Shipit deployment (a documented, supported configuration), these two identifiers are never checked for consistency, so a correctly-signed webhook for organization A can carry a payload that targets organization B's stacks/commits.

### Finding Description
`verify_signature` in `app/controllers/shipit/webhooks_controller.rb` does: [1](#0-0) 

It looks up the `GitHubApp` (and its `webhook_secret`) using: [2](#0-1) 

i.e. `repository_owner` comes from `params.dig('repository','owner','login')` or `params.dig('organization','login')`.

`GitHubApp#verify_webhook_signature` HMACs the *entire* raw body with the secret belonging to whichever organization was picked: [3](#0-2) 

Once verified, `create` parses the same body and dispatches it, unmodified, to every registered handler for the event: [4](#0-3) 

Handlers resolve the target repository from `repository.full_name`, a field completely independent of the `repository.owner.login`/`organization.login` used to pick the signing secret: [5](#0-4) 

`PushHandler` uses that repository lookup to trigger a sync of matching stacks: [6](#0-5) 

`StatusHandler` is even less scoped — it writes a GitHub-reported build status onto *any* `Commit` row in the entire database whose `sha` matches the payload, with no repository/organization check at all: [7](#0-6) 

Multi-organization configuration is an explicitly documented and supported Shipit feature (each organization gets its own `app_id`, `webhook_secret`, and `oauth` config): [8](#0-7) 

**The broken equality/binding:** the engine implicitly assumes
`organization authenticated via webhook_secret == organization that owns the repository/commit being written to`,
but nothing enforces this. The signature only proves "this body was signed with organization A's secret"; it says nothing about whether the `repository.full_name` / `sha` fields inside that same body actually belong to organization A's repositories. Since the attacker fully controls the JSON body they sign, they can freely set those fields to point at a stack that belongs to a different, unrelated organization configured on the same Shipit instance.

### Impact Explanation
This is a cross-repository/cross-tenant write inside the engine's own webhook-processing code, not a misconfiguration:
- An operator who is the legitimate GitHub App/webhook administrator for **one** organization configured in a multi-org Shipit install (and therefore legitimately knows that organization's `webhook_secret`) can forge a signed webhook whose `repository.full_name` or `sha` targets a stack belonging to a **different** organization on the same instance.
- Via `StatusHandler`, this allows writing a fabricated commit status (`state`, `description`, `target_url`, `context`) onto any commit in the system purely by knowing its `sha`, with zero relationship to the organization whose secret was used — this can be used to mark a commit "green"/deployable on a stack the attacker does not control, potentially enabling that stack's operators (or CD automation) to deploy code that never actually passed CI.
- Via `PushHandler`, it can force `GithubSyncJob` to run against an arbitrary stack outside the attacker's organization, an unauthorized cross-repository action initiated by an entity that only proved control of a *different* repository/organization.

This matches the "Critical — cross-repository writes" impact bucket: an organization's authenticated identity (via its own `webhook_secret`) is used to write into a repository/stack that authentication was never meant to authorize.

### Likelihood Explanation
Requires the attacker to be an entity that legitimately administers at least one GitHub organization/App wired into a shared, multi-org Shipit deployment (a supported and documented topology) — a scenario plausible for any Shipit instance shared across multiple teams/orgs, which is exactly the use case the multi-org config in `secrets.development.example.yml` exists for. No compromise of the victim organization's secret, no Shipit session, and no privileged Shipit account are required — only knowledge of the attacker's *own* organization's webhook secret, which they possess by design.

### Recommendation
Bind the two identifiers together: after selecting the `GitHubApp`/secret via `repository_owner`, verify that every repository-scoped field the handlers will act on (`repository.full_name`'s owner, or the owning repository of any `Commit` matched by `sha`) actually belongs to that same authenticated organization before dispatching to handlers. At minimum, `StatusHandler` should scope its `Commit` lookup by the repository/organization that produced a verified signature, not by a bare, globally-unique-looking `sha`.

### Proof of Concept
1. Shipit is configured for two organizations, `attacker-org` and `victim-org`, each with its own `webhook_secret` (per `config/secrets.development.example.yml`'s multi-org schema). The attacker legitimately administers `attacker-org`'s GitHub App and therefore knows `attacker-org`'s `webhook_secret`.
2. Attacker crafts a `status` webhook body:
```json
{
  "sha": "<sha of a commit belonging to victim-org's stack>",
  "state": "success",
  "context": "ci/build",
  "target_url": "https://attacker.example/fake",
  "repository": { "owner": { "login": "attacker-org" } }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(attacker-org's webhook_secret, body)>` and POSTs it to `/webhooks` with `X-Github-Event: status`.
4. `verify_signature` calls `Shipit.github(organization: "attacker-org")` and successfully verifies the signature with `attacker-org`'s own secret.
5. `create` dispatches the parsed body to `StatusHandler`, which runs `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }`, writing a forged "success" status onto the victim-org commit — even though the request was authenticated only against `attacker-org`.

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
