### Title
Webhook signature is verified against `repository.owner.login` / `organization.login` while the event is dispatched against `repository.full_name` — cross-organization/cross-repository writes - (File: app/controllers/shipit/webhooks_controller.rb, app/models/shipit/webhooks/handlers/handler.rb)

### Summary
`WebhooksController#verify_signature` selects the GitHub App (and thus the HMAC secret) to check the `X-Hub-Signature` against using `repository_owner`, which is read from the payload's `repository.owner.login` field (falling back to `organization.login`). However, every `Handler` subclass (`PushHandler`, `StatusHandler`, `CheckSuiteHandler`, etc.) resolves the target `Repository`/`Stack` using a *different* payload field: `repository.full_name` (`app/models/shipit/webhooks/handlers/handler.rb:36-38`). In a multi-organization Shipit deployment (as documented in `config/secrets.development.example.yml` and `docs/setup.md`), these two fields are never cross-checked, so the org whose secret authenticates the request and the repository the handler actually mutates can be made to disagree.

### Finding Description
The verification path:
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
  head(422) unless verified
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [1](#0-0) 

selects the per-organization `webhook_secret` (see the multi-org config schema) based solely on `repository.owner.login`.

The dispatch path used by every handler to decide *which* `Repository`/`Stack` the event acts on is:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [2](#0-1) 

`repository.owner.login` and `repository.full_name` are independent, attacker-controlled JSON fields inside the same raw POST body that the HMAC only guarantees was not tampered with — it does not guarantee any *semantic* relationship between these two fields. An attacker who legitimately owns/administers one organization (`org-A`) already onboarded to this multi-tenant Shipit instance (and therefore who genuinely knows `org-A`'s `webhook_secret`, since GitHub webhook secrets are typically set by whoever configures the GitHub App/webhook for their own org) can:

1. Build a JSON payload with `repository.owner.login = "org-A"` and `repository.full_name = "victim-org/victim-repo"` (and `organization.login` absent or also spoofed to `org-A` for the fallback path).
2. Sign it with `org-A`'s `webhook_secret` using `sha1=HMAC(secret, raw_body)`.
3. POST it to the shared webhook endpoint with `X-Github-Event: push` (or `status`/`check_suite`).

`verify_signature` resolves `Shipit.github(organization: "org-A")` and verifies successfully (`lib/shipit/github_app.rb:76-83`). The handler then resolves the target stack via `Repository.from_github_repo_name("victim-org/victim-repo")` — a completely different, unrelated tenant/org — and calls `stack.sync_github(expected_head_sha: params.after)` for `push` events [3](#0-2) , or sets commit statuses / check-run state for `status`/`check_suite` events on that victim stack.

This is the direct analog of the report's root cause: a check performed against one field (`amount`/here, `repository.owner.login`) gates an action that is actually keyed off a different field (`minAmount` comparison/here, `repository.full_name`) — the binding "organization that authenticated" vs "repository that is written" is broken.

### Impact Explanation
On a Shipit instance configured with the documented multi-organization `github:` block, this allows an attacker who administers one tenant organization to forge webhook events (`push`, `status`, `check_suite`) that are authenticated as their own org but are processed against an arbitrary victim stack/repository hosted by a different tenant on the same instance. Concretely this enables:
- Forcing `GithubSyncJob` to run for a victim stack with an attacker-chosen `expected_head_sha`, corrupting the stack's known git history state.
- Forging `status`/`check_suite` webhooks to inject fake commit statuses / check-run results on a victim's commits, which Shipit's `ci.require` / merge-queue / continuous-deployment gating relies on to decide whether a commit is deployable — this can be used to make an otherwise CI-failing commit appear deployable, leading to an unauthorized deploy of a victim stack.
This crosses the repository-write / tenant boundary that the per-organization webhook secret is supposed to enforce, meeting the "cross-repository writes" / "unauthorized deploy" bar.

### Likelihood Explanation
Requires: (a) the deploying instance to use the multi-organization `github:` configuration with distinct `webhook_secret`s per org (a documented, supported setup), and (b) the attacker to control/administer at least one of the onboarded organizations (and thus know that org's webhook secret, which is normal for anyone setting up their own GitHub App/webhook integration). No privileged Shipit account, `ApiClient` token, or GitHub token belonging to the victim is needed — only knowledge of one's own org's webhook secret and the ability to POST to the public webhook endpoint, which is unauthenticated by design (protected only by the HMAC). This is a plausible, low-effort scenario for any Shipit deployment shared across multiple GitHub organizations/customers.

### Recommendation
After signature verification succeeds, re-derive `repository_owner`/the acting organization strictly from the same trusted source used for dispatch, and reject the request if `repository.owner.login` (used to pick the secret) does not match the owner portion of `repository.full_name` (used by handlers). Concretely, in `WebhooksController#verify_signature`, compare `params.dig('repository','owner','login')` against `params.dig('repository','full_name')&.split('/')&.first` and `head(422)` on mismatch, or better, have `Handler#repository_name`/`#stacks` only ever trust the same `repository_owner` value that was verified, refusing to resolve stacks whose owner differs from the verified organization.

### Proof of Concept
```ruby
# Attacker administers "org-a" on a multi-org Shipit instance and knows its webhook_secret.
secret = "org-a-webhook-secret" # legitimately known by attacker for their own org

payload = {
  ref: "refs/heads/main",
  after: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef", # attacker-chosen SHA
  repository: {
    owner: { login: "org-a" },        # used by WebhooksController#repository_owner for signature check
    full_name: "victim-org/victim-repo" # used by Handler#repository_name to pick the actual stack
  }
}.to_json

signature = "sha1=" + OpenSSL::HMAC.hexdigest("sha1", secret, payload)

# POST to /github_webhooks (documented callback path) with:
# X-Github-Event: push
# X-Hub-Signature: <signature>
# body: payload
#
# WebhooksController#verify_signature resolves Shipit.github(organization: "org-a") and
# succeeds because the signature matches org-a's secret.
# PushHandler#stacks then resolves Repository.from_github_repo_name("victim-org/victim-repo"),
# an org the attacker does not control, and calls stack.sync_github(expected_head_sha: "deadbeef...")
# on the victim's stack.
``` [4](#0-3) [2](#0-1) [3](#0-2)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
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
