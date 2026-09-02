### Title
Webhook signature verification keys off `repository.owner.login`, but every event handler dispatches on `repository.full_name` — ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to validate the inbound webhook against based on `repository.owner.login` (with `organization.login` as fallback), but every `Shipit::Webhooks::Handlers::Handler` subclass (used by `push`, `status`, `check_suite`, `pull_request`, etc.) resolves the actual `Repository`/`Stack` to act on from a *different* field of the same attacker-supplied JSON body: `repository.full_name`. Nothing enforces that these two fields refer to the same repository/organization, so an attacker who can satisfy the signature check for *any one* configured organization can forge a payload whose `full_name` points at a repository belonging to a completely different, unrelated organization tracked by the same Shipit instance.

### Finding Description
The signature check:
```ruby
# app/controllers/shipit/webhooks_controller.rb
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [1](#0-0) 

selects the `GithubApp` config (and thus the `webhook_secret` used for HMAC verification) using `repository.owner.login` from the payload.

`GithubApp#verify_webhook_signature` explicitly no-ops when that organization has no configured `webhook_secret`:
```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
``` [2](#0-1) 

This is a documented, supported configuration — `docs/setup.md` explicitly calls the webhook secret "optional", and the test fixtures (`test/dummy/config/secrets_double_github_app.yml`) show a real multi-organization setup where one org (`OrgTwo`) has `webhook_secret: # nil` while another (`OrgOne`) has a real secret configured. [3](#0-2) 

Meanwhile, every handler resolves the target repository using an entirely different payload field:
```ruby
# app/models/shipit/webhooks/handlers/handler.rb
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [4](#0-3) 

`PushHandler#process` then uses that resolved stack set to trigger a sync directly:
```ruby
def process
  stacks
    .not_archived
    .where(branch:)
    .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
end
``` [5](#0-4) 

Because a single Rails/Shipit deployment can host multiple GitHub Apps/organizations (as shown by `test/dummy/config/secrets_double_github_app.yml`), and because `verify_webhook_signature` trivially returns `true` for any organization configured without a webhook secret, an attacker only needs to control (or know is unprotected) *one* organization in the deployment. They can then POST to `/webhooks` with:
- `repository.owner.login` (and/or `organization.login`) set to the unprotected organization — satisfying `verify_signature`.
- `repository.full_name` set to `"<protected-org>/<any-tracked-repo>"` — which is what the handler actually acts on.

This breaks the intended binding "organization that authenticated == repository that is written." The verified organization and the mutated/synced repository are never checked to be the same entity.

### Impact Explanation
This lets an unprivileged attacker forge `push` (and other) webhook events for repositories/stacks that belong to a different, protected organization than the one whose (weak/absent) secret they satisfied. For a `push` webhook this drives `Stack#sync_github(expected_head_sha: ...)`, which is the same mechanism used for legitimate GitHub-triggered syncs and (for stacks with `continuous_deployment: true`, as seen in fixture stacks such as `shipit_canaries`) feeds directly into automatic deploy triggering. This crosses a repository/organization trust boundary using forged, unauthenticated input — an unauthorized influence over another organization's stack, satisfying the "unauthorized deploy" / cross-repository write class of impact.

### Likelihood Explanation
High for any Shipit deployment configured with more than one GitHub organization/App (a supported, documented configuration — see `docs/setup.md` and the dedicated `secrets_double_github_app.yml` fixture) where at least one organization omits `webhook_secret` (explicitly documented as optional). No credentials, tokens, or repository write access are required — only knowledge that one tenant organization in the deployment has no webhook secret configured, which is externally observable behavior (e.g., by testing whether unsigned webhooks are accepted for that org) but not always intuitive to operators, since the impact leaks into every other tenant's stacks.

### Recommendation
Bind the two decisions together: after locating the target `Repository`/`Stack` via `repository.full_name`, re-derive the organization used for signature verification from that resolved repository's actual `owner`, or verify that `repository.owner.login` matches the owner portion of `repository.full_name` before dispatching to any handler. Alternatively, always require a `webhook_secret` to be configured for every organization (removing the `return true unless webhook_secret` bypass), so that no organization can be used as a "free pass" to authenticate payloads referencing other organizations' repositories.

### Proof of Concept
Given a deployment configured per `test/dummy/config/secrets_double_github_app.yml` (OrgOne has a real `webhook_secret`; OrgTwo has none):
1. Attacker sends `POST /webhooks` with header `X-Github-Event: push` and no valid `X-Hub-Signature` (or an arbitrary one).
2. Body:
```json
{
  "ref": "refs/heads/master",
  "after": "deadbeef",
  "repository": {
    "owner": { "login": "OrgTwo" },
    "full_name": "OrgOne/protected-repo"
  }
}
```
3. `WebhooksController#verify_signature` computes `repository_owner == "OrgTwo"`, loads `Shipit.github(organization: "OrgTwo")`, whose `webhook_secret` is `nil`, so `verify_webhook_signature` returns `true` unconditionally — the request passes signature verification despite not being signed by GitHub at all.
4. `Webhooks.for_event('push')` dispatches to `PushHandler`, whose `repository_name` resolves to `"OrgOne/protected-repo"` (unrelated to the "authenticated" `OrgTwo`), and `stack.sync_github(expected_head_sha: 'deadbeef')` is invoked on `OrgOne`'s stack(s) — a forged sync/deploy trigger for a repository the attacker never authenticated against.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** test/dummy/config/secrets_double_github_app.yml (L41-46)
```yaml
    OrgTwo:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
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
