### Title
Webhook signature verified against `repository.owner.login`, but handlers act on the unverified `repository.full_name` field, allowing cross-repository forged webhooks - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization secret to verify the HMAC signature with based on `repository.owner.login` (or `organization.login`) parsed straight out of the unverified JSON body. Every webhook handler, however, resolves the target `Stack`/`Repository` using a completely different field from that same unverified body: `repository.full_name`. The signature never binds these two fields together, so a party who legitimately controls one org's GitHub App configuration in this Shipit instance can forge a validly-signed webhook whose `owner.login` matches their own org (so verification passes) while `full_name` points at an unrelated victim repository/stack tracked by the same Shipit instance.

### Finding Description
`verify_signature` computes `repository_owner` from the raw, not-yet-verified payload and uses it to pick the org-specific GitHub App/secret to validate the signature against: [1](#0-0) 

All webhook handlers inherit from `Handler`, which independently derives the target repository from `payload.dig('repository', 'full_name')`, with no relationship to `repository_owner`: [2](#0-1) 

Because the HMAC (`verify_webhook_signature`) covers the raw body as an opaque blob, it only proves "whoever signed this body knew the secret associated with `repository.owner.login`" — it does not prove any relationship between `owner.login` and `full_name` inside that same body: [3](#0-2) 

Shipit explicitly supports multiple independently configured GitHub Apps/orgs in `secrets.yml`, each with its own separate `webhook_secret`, `app_id`, etc.: [4](#0-3) 

Each GitHub App's webhook secret is chosen by whoever creates that App (per `docs/setup.md`), so the administrator of *one* configured org's App legitimately knows their own org's secret while having no privileges over any other org/repository tracked by the same Shipit deployment.

**The equality broken**: `organization authenticated by the HMAC (repository.owner.login)` ≠ `repository actually written to (repository.full_name)`.

Concretely, `PushHandler#process` uses `stacks` (resolved via `full_name`) to call `stack.sync_github(expected_head_sha: params.after)`: [5](#0-4) 

and `StatusHandler#process` performs an even broader, org-unscoped lookup — `Commit.where(sha: params.sha)` — and injects a fabricated commit status for any matching commit in the whole instance, again with no ownership check against the org that produced the valid signature: [6](#0-5) 

### Impact Explanation
An attacker who administers their own GitHub App entry configured in this Shipit instance (and thus knows that org's `webhook_secret` — not a Shipit `ApiClient` token, GitHub App private key, or Shipit session) can POST directly to `/webhooks` with a signature valid for their own org but a `repository.full_name` pointing at a victim stack/repository they have no rights to. This lets them:
- Force `GithubSyncJob`/`sync_github` on a victim stack via forged `push` events.
- Inject arbitrary fabricated commit statuses (`state`, `context`, `target_url`) onto arbitrary commits system-wide via `status` events, which can flip a commit's `success`/`failure` state for continuous-deployment gating and merge-related checks that the victim stack relies on.

Depending on the victim stack's configuration (continuous deployment enabled, status-based gating), this can escalate into an unauthorized deploy trigger on a repository the attacker does not control, which maps to the Critical "unauthorized deploy" impact category. I was not able to fully trace every downstream consumer of forged statuses (e.g., exact CD-trigger and merge-queue code paths) within the remaining investigation budget, so the precise blast radius of the forged status beyond `StatusHandler`/`PushHandler` should be validated further before treating this as unconditionally Critical.

### Likelihood Explanation
High: this requires no compromise of Shipit itself — only knowledge of a webhook secret for *any one* org configured on the instance, which its own administrator legitimately possesses. It requires no GitHub interaction at all; the attacker crafts an arbitrary HTTP request directly to the public `/webhooks` endpoint.

### Recommendation
Bind the field used to select the verification secret to the field used to resolve the affected repository/stack. Concretely, verify that `repository.owner.login` (used to pick the secret) matches the owner encoded in `repository.full_name` before dispatching to handlers, or resolve the target `Repository`/`Stack` using `repository.owner.login` consistently rather than trusting `full_name` independently. Reject the webhook if these two values diverge.

### Proof of Concept
1. Attacker administers their own GitHub App "AttackerApp" installed for org `attacker-org`, configured in this Shipit instance's `secrets.yml` with `webhook_secret: "attacker-secret"` (this is legitimate — they created that App).
2. Attacker crafts a JSON body for a `push` event:
```json
{
  "ref": "refs/heads/main",
  "after": "deadbeef...",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(body, "attacker-secret")>` and sets `X-Github-Event: push`.
4. `WebhooksController#verify_signature` computes `repository_owner = "attacker-org"`, loads `attacker-org`'s GitHub App, and successfully verifies the signature (`app/controllers/shipit/webhooks_controller.rb:24-38`).
5. `PushHandler.call(params)` runs, resolves `stacks` via `payload.dig('repository','full_name') == "victim-org/victim-repo"` (`app/models/shipit/webhooks/handlers/handler.rb:32-38`), and triggers `sync_github` on the victim's stack — despite the attacker having no relationship to `victim-org`.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-61)
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

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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
