### Title
Webhook signature is verified against the org named in the payload while the affected repository/stack is selected from a different, unverified payload field - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/handler.rb])

### Summary
The M-22 bug class is "a value the code trusts is not actually the value that was checked" — the vault checked nothing about the fees it stored. The analog here is a **binding break between the organization whose secret is used to verify the HMAC signature and the repository whose Stacks are subsequently mutated by the handler that runs on that same, "verified" payload**.

### Finding Description
`WebhooksController#verify_signature` picks which GitHub App/organization's `webhook_secret` to use for HMAC validation from a field inside the untrusted request body itself: [1](#0-0) [2](#0-1) 

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(...)
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```

Once the signature check passes, `create` dispatches the *same, attacker-controlled* payload to handlers: [3](#0-2) 

Every handler (`PushHandler`, `CheckSuiteHandler`, `StatusHandler`, etc.) resolves the target `Repository`/`Stack` from a **different** field of that same payload — `repository.full_name` — never cross-checked against `repository.owner.login`/`organization.login` that was used to select the verifying secret: [4](#0-3) [5](#0-4) 

So the equality that should hold — `organization authenticated == organization/repository written` — is never enforced. Only `organization authenticated == repository_owner used for HMAC key selection` is enforced; `full_name` used for the actual DB/Stack lookup is independent of that check.

`Shipit.github(organization:)` config supports multiple tenants, each with its own `webhook_secret`, exactly as shown in `config/secrets.development.shopify.yml` (multiple orgs, each with its own `webhook_secret`), confirming this is a genuinely multi-tenant surface where one organization's admin legitimately possesses their own org's secret but not another's: [6](#0-5) 

### Impact Explanation
An attacker who administers (or has compromised) one org's GitHub App configured on a shared Shipit instance knows that org's `webhook_secret` (they set it up). They can POST a forged webhook to `/github/webhooks` (or whatever the mount path is) with:
- `repository.owner.login` / `organization.login` = their own org (so `verify_signature` succeeds using their own secret)
- `repository.full_name` = `"victim-org/victim-repo"` (a repository belonging to a completely different, unrelated tenant on the same Shipit instance)

Because `Handler#stacks` only looks at `full_name`, the forged payload is applied to the victim repository's stacks: `PushHandler` triggers `stack.sync_github`, `CheckSuiteHandler`/`StatusHandler` write commit statuses/check runs on the victim's commits, etc. This is a **cross-tenant/cross-repository write performed under another organization's authorization boundary** — the exact "organization authenticated versus repository written" mismatch called out in the analog rules.

The severity is bounded by what each handler does with the spoofed data (mostly triggering syncs/statuses, not code execution), so this sits at repository-state-integrity impact (spurious syncs, forged commit statuses that could gate/allow a deploy) rather than RCE. It does qualify as an unauthorized cross-repository write of state used to drive deploy decisions (forged `commit_status` / `check_suite` events can flip a Stack's deployability), which matches the "cross-repository writes" / "unauthorized deploy" impact category when a victim stack's continuous-deployment gating relies on GitHub status/check events.

### Likelihood Explanation
Requires the Shipit install to be configured for multiple GitHub organizations (explicitly supported and documented) and requires the attacker to control (or have compromised) one of those organizations' GitHub Apps — a real but non-trivial precondition. No Shipit session, `ApiClient` token, or private key is needed; only knowledge of one's own configured org's `webhook_secret`, which is normal legitimate access to that org's own GitHub App settings.

### Recommendation
After selecting `github_app` via `repository_owner` and verifying the signature, additionally assert that `params.dig('repository', 'full_name')`'s owner segment matches `repository_owner` before dispatching to handlers, e.g.:

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  return head(422) unless verified_signature?(github_app)
  return head(422) unless repository_owner_matches_full_name?
  ...
end
```

### Proof of Concept
1. Configure Shipit with two orgs, `attacker-org` and `victim-org`, each with their own `webhook_secret` (as in `config/secrets.development.shopify.yml`).
2. As an admin of `attacker-org`'s GitHub App, compute `sha1=HMAC(attacker_org_secret, body)` over a crafted JSON body:
   ```json
   {
     "ref": "refs/heads/master",
     "after": "deadbeef",
     "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" }
   }
   ```
3. POST to the webhooks endpoint with header `X-Github-Event: push` and `X-Hub-Signature: sha1=<computed>`.
4. `verify_signature` resolves `Shipit.github(organization: "attacker-org")` and validates successfully against the attacker's own secret.
5. `PushHandler#stacks` resolves `Repository.from_github_repo_name("victim-org/victim-repo")` and calls `stack.sync_github` on the victim's stack, i.e., the attacker triggered a state change on a repository they do not control, using their own org's credentials to pass the signature check. [7](#0-6)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L1-64)
```ruby
# frozen_string_literal: true

module Shipit
  class WebhooksController < ActionController::Base
    skip_before_action :verify_authenticity_token, raise: false
    before_action :check_if_ping, :drop_unhandled_event, :verify_signature

    respond_to :json

    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end

    private

    def drop_unhandled_event
      # Acknowledge, but do nothing
      head(204) unless Shipit::Webhooks.for_event(event).present?
    end

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
  end
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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** config/secrets.development.shopify.yml (L5-23)
```yaml
github:
  somegithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
  someothergithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
```
