## Confirmed root cause

`WebhooksController#verify_signature` selects which per-organization webhook secret to verify the HMAC against using a field taken directly from the *unverified* JSON body:

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
``` [1](#0-0) 

The HMAC only proves the request was signed with *the secret belonging to whichever org name is in `repository.owner.login`/`organization.login`*. It does **not** bind that org to any other field of the payload. Every event handler, however, resolves the actual `Repository`/`Stack` to act on using a completely different field: `repository.full_name`:

```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [2](#0-1) 

`Repository.from_github_repo_name` splits `full_name` on `/` and looks up by `owner`/`name` independently of `repository.owner.login`: [3](#0-2) . Multiple handlers (`PushHandler`, `StatusHandler`, the pull-request handlers, `MembershipHandler`, etc.) also use `repository.full_name` / `sha` to locate the target repository/commit, completely decoupled from `repository_owner`. E.g. `StatusHandler` creates a commit status purely from `params.sha` with no repository/org check at all: [4](#0-3) , and `PushHandler` triggers a `GithubSyncJob`/`stack.sync_github` for stacks matched via `full_name` and `branch`: [5](#0-4) .

`Shipit.github(organization:)` is explicitly designed to support **multiple independent GitHub organizations/apps in one Shipit instance**, each with its own `webhook_secret` (see `config/secrets.development.shopify.yml` listing `somegithuborg` / `someothergithuborg`, each with a distinct `webhook_secret`) [6](#0-5) , resolved via `github_app_config` keyed strictly by org name: [7](#0-6) .

## The broken binding

`organization whose webhook_secret authenticated the request` ≠ `repository.full_name that the handler actually writes to`.

Before the attack, these two should be equal (the org that owns the signing secret should be the org that owns the target repository). The controller only checks the first; nothing enforces that `repository.full_name`'s owner segment matches `repository_owner`.

### Title
Webhook signature verification binds the wrong field, allowing cross-organization event forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks the GitHub organization (and thus the HMAC secret) to verify a webhook against from `repository.owner.login`/`organization.login`, but every downstream event handler resolves the actual repository/stack/commit to act on from the independent `repository.full_name` (or bare `sha`) field. In a Shipit deployment configured for multiple GitHub organizations (as documented and supported by `Shipit.github(organization:)`), an attacker who legitimately controls one configured organization (and therefore knows/can produce a valid signature with that organization's `webhook_secret`) can forge a webhook whose `repository.owner.login` names their own org (to pass verification) while `repository.full_name` names a repository belonging to a *different* organization also hosted on the same Shipit instance, causing Shipit to act on that other organization's stack.

### Finding Description
1. `verify_signature` computes `repository_owner` from the raw JSON body before any authenticity check, then fetches that organization's `GitHubApp` and verifies `X-Hub-Signature` against it: [8](#0-7) .
2. Once verification passes, `Webhooks.for_event(event).each { |handler| handler.call(params) }` dispatches the **entire raw payload**, including `repository.full_name`, to handlers [9](#0-8) .
3. Handlers such as `PushHandler` and the `PullRequest::*Handler`s locate the target `Repository`/`Stack` purely via `repository.full_name` using `Repository.from_github_repo_name` [2](#0-1) [3](#0-2) , and `StatusHandler` locates target commits purely via `sha`, with no organization scoping at all [10](#0-9) .
4. Nothing anywhere cross-checks that `repository.owner.login` (the value used to select the verifying secret) matches the owner segment of `repository.full_name` (the value used to select the acted-upon resource).

Because `repository.owner.login` and `repository.full_name` are independently attacker-controlled fields within the same signed JSON body, an attacker who owns/administers Org A (one of possibly several orgs configured on this Shipit instance) can:
- Set `repository.owner.login` = `"org-a"` (so `verify_signature` fetches Org A's `webhook_secret`, which the attacker knows because they configured/administer Org A's GitHub App and can trigger real deliveries or simply compute the HMAC offline since they hold the secret).
- Set `repository.full_name` = `"org-b/target-repo"` (a repository belonging to a *different*, victim organization also hosted on the same instance).
- Sign the whole payload with Org A's `webhook_secret`.

`verify_webhook_signature` succeeds because it only checks the signature against Org A's secret and the raw body — it has no knowledge of, or care about, `full_name`'s owner. The event is then dispatched with `repository.full_name` pointing at Org B's stack.

### Impact Explanation
This breaks the deployment-trust boundary between tenants of a multi-organization Shipit deployment: an authenticated-but-unprivileged-with-respect-to-Org-B attacker (who only administers Org A) can act as if they controlled Org B's GitHub events. Concretely reachable impacts include:
- Forge a `push` event for Org B's stack (`repository.full_name` = victim repo, correct `branch`) to trigger `GithubSyncJob`/`stack.sync_github`, causing Shipit to re-sync/re-evaluate commits it believes came from GitHub for a stack it has no real authorization boundary over via the webhook channel.
- Forge a `status` event with an arbitrary `sha` value, `state: "success"`, and fabricated `context`/`description` to create a fake passing CI status on any commit hash string present in Shipit's `commits` table for the victim's stack — this can satisfy `ci.require` checks in `shipit.yml` and enable an **unauthorized deploy** of a commit that never actually passed CI, since `StatusHandler` performs zero authorization/ownership check tying the sha to a specific repository owner.
- Trigger pull-request/review-stack provisioning, archiving, or label-driven behavior (`opened_handler.rb`, `labeled_handler.rb`, etc.) against Org B's review stacks by supplying `repository.full_name` for Org B while signing with Org A's secret.

This matches the required High/Critical impact class of "an unauthorized deploy" via forged CI status combined with cross-organization writes, achieved purely by exploiting the mismatch between the authenticating org and the acted-upon repository.

### Likelihood Explanation
Requires a Shipit deployment configured with more than one GitHub organization (explicitly supported and documented via `Shipit.github(organization:)`/`github_organizations`), and requires the attacker to legitimately control at least one of those organizations (i.e., know that org's `webhook_secret`, which they would if they are the org's GitHub App administrator — not a Shipit account/API-client credential, and not `GITHUB_TOKEN`/`api_clients_secret`). No Shipit session or privileged account is needed; only knowledge of one tenant's webhook secret, which by design is held outside Shipit by each organization's own administrators. This is a realistic scenario in exactly the kind of shared/multi-tenant Shipit installation this configuration mechanism exists to support.

### Recommendation
After signature verification succeeds, validate that the organization used to verify the signature (`repository_owner`) matches the owner portion of `repository.full_name` (and `organization.login` where applicable) before dispatching to handlers; reject the webhook (422) on mismatch. Alternatively, derive the verifying organization strictly from the resolved `Repository` record for `repository.full_name` rather than from a same-payload, unverified `owner.login` field, so the two are never independently attacker-controllable.

### Proof of Concept
1. Configure Shipit with two organizations, `org-a` and `org-b`, each with its own `webhook_secret` (as in `config/secrets.development.shopify.yml`), and a stack for `org-b/victim-repo`.
2. As the administrator of `org-a` (attacker), compute:
   ```ruby
   payload = {
     ref: "refs/heads/main",
     after: "<attacker chosen sha present in Shipit db for org-b/victim-repo>",
     repository: { owner: { login: "org-a" }, full_name: "org-b/victim-repo" }
   }.to_json
   signature = "sha1=" + OpenSSL::HMAC.hexdigest("sha1", org_a_webhook_secret, payload)
   ```
3. POST to `/webhooks` with `X-Github-Event: push`, `X-Hub-Signature: signature`, body `payload`.
4. `verify_signature` resolves `repository_owner` = `"org-a"`, fetches Org A's `GitHubApp`, and `verify_webhook_signature` succeeds (signature matches Org A's secret).
5. `PushHandler.call(params)` resolves `stacks` via `Repository.from_github_repo_name("org-b/victim-repo")`, matching Org B's stack, and triggers `stack.sync_github(expected_head_sha: ...)` — an action against Org B's stack authorized only by Org A's secret. The equivalent construction with the `status` event and an arbitrary `sha` creates a forged CI status on Org B's commit, which can then satisfy `ci.require` and enable a deploy.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-25)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class StatusHandler < Handler
        params do
          requires :sha, String
          requires :state, String
          accepts :description, String
          accepts :target_url, String
          accepts :context, String
          accepts :created_at, String

          accepts :branches, Array do
            requires :name, String
          end
        end

        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
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

**File:** lib/shipit.rb (L196-200)
```ruby
  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
  end
```
