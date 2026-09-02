### Title
Webhook signature verification is bypassed per-organization when `webhook_secret` is blank, allowing forged `push`/`status`/`check_suite` events to be written against a repository the attacker does not control - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App configuration's secret to verify a webhook's HMAC against based on `repository.owner.login` (or `organization.login`) taken from the *unverified* JSON body, but the handlers that actually act on the payload key off a different field, `repository.full_name`, to decide which `Stack`/`Repository` gets mutated. `GitHubApp#verify_webhook_signature` also treats a blank/unconfigured `webhook_secret` as automatically verified (`return true unless webhook_secret`). This breaks the intended binding "organization that authenticated" == "repository that is written."

### Finding Description
`verify_signature` derives the org used for verification purely from body content: [1](#0-0) 
```
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(...)
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [2](#0-1) 

`verify_webhook_signature` no-ops for any org whose secret is unset: [3](#0-2) 
```
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
```

Meanwhile, the actual per-event handler resolves the target `Repository`/`Stack` from an entirely different JSON field, `repository.full_name`, not `repository.owner.login`: [4](#0-3) 
```
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
```

`PushHandler` then triggers a GitHub sync for whatever stack matches that `full_name`: [5](#0-4) 

Because the field used to pick the *verification key* (`repository.owner.login`) and the field used to pick the *repository acted upon* (`repository.full_name`) are independent, unauthenticated attacker-supplied JSON fields, they need not agree. Multi-organization Shipit installations (the documented/templated configuration format, see `config/secrets.development.shopify.yml` and `test/dummy/config/secrets_double_github_app.yml`, which ship with `webhook_secret: # nil` by default) are directly affected: as soon as any one configured organization is left with a blank `webhook_secret` (the documented default), `verify_webhook_signature` for that org always returns `true` regardless of the actual `X-Hub-Signature` header.

An attacker can therefore POST to `/webhooks` with:
- `X-Github-Event: push` (or `status`, `check_suite`, etc.)
- a body where `repository.owner.login` names the organization with no configured secret (selecting the always-pass verifier)
- `repository.full_name` naming a *different*, actually tracked victim repository/stack

`verify_signature` passes (secret-less org verifies unconditionally), and `Shipit::Webhooks.for_event(event)` handlers then run against the victim repository named in `full_name`, e.g. forcing `stack.sync_github(expected_head_sha: ...)` on a stack the attacker doesn't own, or injecting fabricated commit statuses via `StatusHandler#process` (`Commit#create_status_from_github!`), or triggering `CheckSuiteHandler` check-run refreshes on arbitrary commits.

### Impact Explanation
This is an authentication-bypass on the webhook trust boundary: the entity whose credential was checked (the org matched by `repository.owner.login`) is not the entity whose state is mutated (`repository.full_name`). Forged `status` events are particularly severe because commit statuses gate whether a commit is deployable/mergeable in Shipit's merge queue and deploy pipeline (`Commit#create_status_from_github!`), so an attacker able to exploit an unconfigured/leaked secret for any one tenant org can inject fabricated "success" statuses for commits belonging to a different, victim-tracked repository, potentially unblocking or manipulating deploy/merge decisions for repositories they have no GitHub access to. This matches the High-impact bucket (escalation past the intended authentication/authorization boundary on stack state).

### Likelihood Explanation
Exploitation requires only one condition that the shipped configuration templates actively encourage: at least one configured GitHub organization in `Shipit.github` with a blank `webhook_secret` (the documented default in `config/secrets.development.shopify.yml` / setup docs is literally `webhook_secret: # nil`). Any installation that has more than one org configured and forgets/declines to set a webhook secret on one of them (e.g., a low-traffic or newly onboarded org) exposes every other tracked repository/stack to forged webhook events, with no signature knowledge needed at all — only knowledge of the secret-less org's login name, which is not secret.

### Recommendation
- Verify the webhook signature using the secret belonging to the organization that actually owns `repository.full_name` (or, better, require them to match and reject on mismatch), not an independently-chosen field.
- Do not treat a blank `webhook_secret` as "verification passed"; either require a secret to be configured for every org, or fail closed (`return false unless webhook_secret`) and document that omitting a secret disables webhook ingestion for that org rather than disabling verification entirely.
- Cross-check that `repository.owner.login` and the owner segment of `repository.full_name` are consistent before dispatching to handlers.

### Proof of Concept
1. Configure two orgs in `Shipit.github`, e.g. `AttackerOrg` (no `webhook_secret` set, matching the documented default) and `VictimOrg` (tracked stack `VictimOrg/app`, with its own secret).
2. POST to `/webhooks` with header `X-Github-Event: status` and body:
```json
{
  "repository": { "owner": { "login": "AttackerOrg" }, "full_name": "VictimOrg/app" },
  "sha": "<victim commit sha>",
  "state": "success",
  "context": "ci/tests"
}
```
   No `X-Hub-Signature` header (or an arbitrary one) is required.
3. `verify_signature` calls `Shipit.github(organization: "AttackerOrg")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` unconditionally (`lib/shipit/github_app.rb:76-83`).
4. `StatusHandler#process` runs against `Commit.where(sha: params.sha)` for the commit named in the payload, which belongs to `VictimOrg/app`, and creates a forged success status for it (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`), even though the attacker never authenticated as, nor holds any signing secret for, `VictimOrg`.

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
