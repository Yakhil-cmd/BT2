### Title
Webhook signature verified against `repository.owner.login`'s GitHub App while event handlers act on `repository.full_name` — cross-tenant repository writes - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/handler.rb`)

### Summary
`WebhooksController#verify_signature` selects the GitHub App (and its `webhook_secret`) to verify the HMAC signature based on `repository.owner.login` (or the `organization.login` fallback) taken from the untrusted request body. All webhook handlers, however, resolve the `Stack`/`Repository` to act on using a *different* field of the same payload: `repository.full_name`, via `Shipit::Webhooks::Handlers::Handler#repository_name` / `#stacks`. Nothing in the code enforces that these two fields agree, so a payload can be legitimately signed as belonging to one tenant while its content operates on another tenant's repository.

### Finding Description
`verify_signature` in `app/controllers/shipit/webhooks_controller.rb` does: [1](#0-0) [2](#0-1) 

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [3](#0-2) 

The signature check only proves the request body was HMAC-signed with the `webhook_secret` belonging to the organization named in `repository.owner.login`. Shipit is explicitly multi-tenant: each org has its own `webhook_secret` in configuration, as seen in `config/secrets.development.shopify.yml`, where multiple independent orgs (`somegithuborg`, `someothergithuborg`) each get their own secret. [4](#0-3) 

After signature verification succeeds, `create` dispatches the parsed JSON body to event handlers unmodified: [5](#0-4) 

Every handler resolves the target repository/stack using `payload.dig('repository', 'full_name')`, a field entirely independent from the `repository.owner.login` field used for signature routing: [6](#0-5) 

```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
```

`Repository.from_github_repo_name` splits `full_name` on `/` and looks the repository up purely by that string, with no cross-check against `repository.owner.login`: [7](#0-6) 

The binding that should hold is: **organization that authenticated the payload == owner of the repository the payload writes to**. The code enforces neither equality nor even a check that `repository.owner.login` and the owner segment of `repository.full_name` match. Because the entire JSON body (not just specific fields) is attacker-controlled before signing, and the attacker fully controls the content of a POST once they know a valid `webhook_secret` for *any* org onboarded to the same Shipit instance, they can set:
- `repository.owner.login = "attacker-org"` (or `organization.login = "attacker-org"`) — used only to select which secret to check against,
- `repository.full_name = "victim-org/victim-repo"` — used by every handler to pick the actual `Stack`.

Since the signature is computed over `request.raw_post` (the full body they crafted), it is trivially valid for the secret Shipit picks (attacker-org's), while the actual mutation target is `victim-org/victim-repo`.

### Impact Explanation
This is a cross-tenant / cross-repository write: an attacker who legitimately administers the webhook for one org onboarded into a multi-org Shipit deployment can forge events (`push`, `status`, `check_suite`, `pull_request`, `membership`, etc.) that are processed as if they came from an entirely different, victim repository/organization. Depending on the handler this enables things like:
- Injecting fabricated commit `status`/`check_suite` results for a victim stack (affecting deploy-gating decisions, e.g. `StatusHandler`),
- Creating/mutating `ReviewStack`s for a victim repository via `PullRequest::OpenedHandler` → `ReviewStackAdapter#find_or_create!`,
- Triggering `GithubSyncJob` for the victim's stack on forged `push` events.

This matches the "cross-repository writes"/"unauthorized deploy" Critical impact bucket, since victim stack state (commits, statuses, review stacks) can be manipulated by a party with no legitimate access to the victim's repository or org, purely because they hold a valid `webhook_secret` for an unrelated onboarded org.

### Likelihood Explanation
This requires the attacker to control the webhook secret of at least one org already onboarded onto the same Shipit instance — a realistic scenario for any organization running Shipit for multiple GitHub orgs/teams, since onboarding a new org's GitHub App is a normal, low-privilege administrative action, not equivalent to trusting that org with access to every other org's repositories. No signature/HMAC forgery is needed; the attacker signs with their own legitimate secret. This is analogous in structure to the referenced Backd finding: a "removal"/binding assumption (there, gauge-liveness; here, org-to-repo consistency) is silently relied upon but never actually checked on-chain/in-code.

### Recommendation
After determining `repository_owner` for secret selection, verify that it matches the owner segment parsed from `repository.full_name` (and/or `organization.login`) before dispatching to handlers; reject the webhook with `422` on mismatch. Alternatively, have handlers derive the repository strictly from the same field used for signature verification, eliminating the two independent code paths.

### Proof of Concept
1. Shipit instance is configured with two onboarded orgs: `attacker-org` (attacker administers its GitHub App/webhook, so they know its `webhook_secret`) and `victim-org` (unrelated, e.g. `shopify`), both present in `Shipit.github` config as in `config/secrets.development.shopify.yml`.
2. Attacker crafts a JSON body for, e.g., the `push` event:
   ```json
   {
     "repository": { "owner": {"login": "attacker-org"}, "full_name": "victim-org/victim-repo" },
     "ref": "refs/heads/main",
     "after": "<attacker-chosen-sha>"
   }
   ```
3. Attacker computes `X-Hub-Signature: sha1=<hmac>` using `attacker-org`'s known `webhook_secret` over the exact raw body.
4. POST directly to `/webhooks` with `X-Github-Event: push`.
5. In `WebhooksController#verify_signature`, `repository_owner` resolves to `"attacker-org"`, `Shipit.github(organization: "attacker-org")` is fetched, and `verify_webhook_signature` succeeds because the attacker signed with the correct secret for that org.
6. `create` calls `Shipit::Webhooks.for_event('push')`, whose handler resolves `stacks` via `Repository.from_github_repo_name("victim-org/victim-repo")`, acting on the victim's stack (e.g., enqueuing `GithubSyncJob` for `victim-org/victim-repo`) despite the request never being authenticated for that repository/org.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-16)
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

**File:** config/secrets.development.shopify.yml (L1-23)
```yaml
host: 'shipit-engine.myshopify.io'

# For creating an app see: https://github.com/Shopify/shipit-engine/blob/main/docs/setup.md#creating-the-github-app

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
