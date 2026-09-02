### Title
Cross-organization webhook signature confusion allows unauthorized deploys and CI-status/repository-state forgery across tenants - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
The `_computeAvailable()` report describes a class of bug where a value computed on one basis (the boost's own tracked ledger) is then bounded/validated against a different, mismatched basis (the raw current balance, which also contains unrelated funds), so the check does not actually enforce the invariant it's meant to. The structural analog in this Shipit engine is a **verification/action mismatch**: the `WebhooksController` selects and validates a webhook signature using one field extracted from the untrusted JSON body (`repository.owner.login`), but the event handlers that subsequently act on that same body use a **different field** (`repository.full_name`, or in the `status` handler, no repository scoping at all) to decide which `Stack`/`Repository`/`Commit` to mutate. The field that is cryptographically authenticated is not the field that is authorized to act.

### Finding Description
In `app/controllers/shipit/webhooks_controller.rb`: [1](#0-0) [2](#0-1) 

`verify_signature` looks up which `GithubApp`/webhook secret to validate against by reading `repository_owner`, i.e. `params.dig('repository', 'owner', 'login')`, straight out of the attacker-supplied JSON body — before any signature has been checked. It then calls `github_app.verify_webhook_signature(signature, raw_post)` using that organization's configured `webhook_secret` (config supports multiple independent organizations, each with its own secret, as shown in `config/secrets.development.shopify.yml`). If the HMAC matches, the whole raw body — including all other fields — is accepted and dispatched to handlers via `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` in `create`.

Critically, none of the downstream handlers verify that the organization used to select/verify the signature is the same as the organization/repository they act upon:

- `Handler#stacks` and every PR handler resolve the target strictly from `payload.dig('repository', 'full_name')` — a separate, independently attacker-controlled field in the same JSON body: [3](#0-2) [4](#0-3) 

- `StatusHandler` is even less scoped: it doesn't reference `repository` at all, it just matches by raw commit SHA across the entire installation: [5](#0-4) 

- `Repository.from_github_repo_name` splits `full_name` on `/` and does a plain DB lookup by `owner`/`name`, with no relationship at all to `repository.owner.login`: [6](#0-5) 

Because `repository.owner.login` (used to pick the verifying secret) and `repository.full_name` (used to pick the target repo/stack) are two independent keys inside the same attacker-crafted JSON payload, an operator of one tenant organization configured in this Shipit instance — who legitimately knows their own org's `webhook_secret` (they created/administer that GitHub App, per `docs/setup.md`) — can forge a payload where `repository.owner.login` = their own org (so the HMAC computed with their own secret passes `verify_webhook_signature`), while `repository.full_name` (and for `status` events, `sha`) references a repository/commit belonging to a **completely different** organization/tenant hosted on the same Shipit instance.

This breaks the intended binding:
`organization whose secret authenticated the request == organization/repository the handler is authorized to mutate`

before vs. after the attacker's forged request:
- Before: only GitHub, holding org B's real webhook secret, can produce a validly-signed event that causes writes to org B's stacks/commits.
- After: org A's admin, using only org A's own secret, can produce a validly-signed (per the code's logic) event that still causes writes to org B's stacks/commits, because the signature-selecting field and the action-target field are never cross-checked.

### Impact Explanation
This crosses a genuine trust boundary between tenants/organizations hosted by the same Shipit deployment:
- `PushHandler` can trigger `stack.sync_github(expected_head_sha: ...)` for an arbitrary victim stack, which can kick off continuous-delivery-driven deploys for that stack.
- `StatusHandler` can inject arbitrary CI status (`success`/`failure`) for any commit SHA in the entire database (`Commit.where(sha: params.sha)`), regardless of which org the commit belongs to. This lets an attacker forge a passing CI status on a required check, bypassing `ci.require`/blocking-status deploy gating for a victim stack, leading to an unauthorized deploy.
- PR handlers (`opened`/`closed`/`labeled`/etc.) can archive/unarchive/provision review stacks belonging to a different org's repository.

This matches the "Critical - ... an unauthorized deploy, rollback or merge" / "cross-repository writes" impact bar in the rules, assuming a multi-organization Shipit deployment (explicitly supported, per `config/secrets.development.shopify.yml` showing multiple orgs each with independent `webhook_secret`/`oauth`).

### Likelihood Explanation
Requires the attacker to control a GitHub App/webhook secret for at least one organization configured on the same Shipit instance (i.e., be an admin of one tenant), which is not a privileged Shipit account, `ApiClient` token, or GitHub org membership on the victim's side — it is a credential the attacker legitimately holds for their own, unrelated organization. This is realistic for any Shipit deployment serving more than one GitHub organization, which the codebase explicitly supports via per-organization webhook secrets. I was not able to fully confirm from the indexed code whether `Shipit.github(organization:)` performs any additional cross-validation beyond secret lookup (the full body of `lib/shipit.rb` was not available in the index), so there is some uncertainty about whether any other layer mitigates this; based on everything retrievable, no such check exists in the controller or handler layer.

### Recommendation
After signature verification succeeds, re-derive the authorized organization from the same field used for signature selection (`repository.owner.login` / `organization.login`) and require every handler to verify that the resource it is about to mutate (`repository.full_name`'s owner, or the `Stack`/`Commit`'s associated `Repository#owner`) matches that authenticated organization before performing any write. For `StatusHandler` specifically, scope the `Commit.where(sha: ...)` lookup to commits whose `stack.repository.owner` equals the authenticated organization.

### Proof of Concept
1. Shipit is deployed with two tenants configured, e.g. `orga` and `orgb`, each with its own GitHub App and `webhook_secret` (as in `config/secrets.development.shopify.yml`).
2. Attacker administers `orga`'s GitHub App and thus knows `orga`'s `webhook_secret`.
3. Attacker crafts a `push` (or `status`) webhook JSON body:
```json
{
  "repository": { "owner": { "login": "orga" }, "full_name": "orgb/victim-repo" },
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>"
}
```
4. Attacker computes `X-Hub-Signature: sha1=HMAC(orga_webhook_secret, body)` and POSTs to `/webhooks`.
5. `WebhooksController#verify_signature` reads `repository_owner` → `"orga"`, fetches `Shipit.github(organization: "orga")`, and validates successfully since the attacker signed with `orga`'s real secret.
6. `Shipit::Webhooks.for_event('push')` dispatches to `PushHandler`, which resolves `stacks` via `Repository.from_github_repo_name("orgb/victim-repo")` — a repository belonging to a different organization than the one that authenticated — and calls `stack.sync_github(...)`, triggering sync/deploy logic on `orgb`'s stack despite the request never being signed by `orgb`. [7](#0-6) [3](#0-2) [5](#0-4)

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
