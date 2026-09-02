### Title
Webhook signature verification is bound to `repository.owner.login` while event processing is bound to `repository.full_name` — cross-organization webhook forgery in multi-org deployments - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
### Finding Description
`WebhooksController#verify_signature` selects which GitHub App/webhook secret to check the HMAC signature against using `repository_owner`, an attacker-controlled field taken straight from the unauthenticated request body: [1](#0-0) [2](#0-1) [3](#0-2) 

After signature verification succeeds, `create` dispatches the *entire* raw payload to the event handlers unchanged: [4](#0-3) 

Every handler then resolves the target `Repository`/`Stack` not from `repository.owner.login` (the field used for signature selection) but from `repository.full_name`: [5](#0-4) [6](#0-5) 

In Shipit's documented multi-organization configuration, each GitHub organization has its own, independently-configured `webhook_secret`: [7](#0-6) 

Because `verify_signature` picks the secret keyed by the untrusted `repository.owner.login` field, and the downstream handlers act on the untrusted `repository.full_name` field, these two fields are never checked for consistency. An attacker who legitimately knows the webhook secret for **one** configured organization (e.g., they administer their own GitHub App/organization "org-a" that is onboarded onto the same Shipit instance) can craft a payload where `repository.owner.login = "org-a"` (so the correct, known secret is selected and the HMAC computed over the raw body validates) but `repository.full_name = "victim-org/victim-repo"`. `verify_signature` passes because it only checked the secret for `org-a`; the handler then acts on `victim-org/victim-repo`'s stacks, commits, PRs, or memberships.

This is the same class of bug as the report's `_beforeTokenTransfer` mismatch: one field (`from`, analogous to `repository.owner.login`) is the field actually checked, while a different field/action (the burn target, analogous to `repository.full_name`) is the one actually acted upon — the check and the effect are bound to different data, breaking the intended binding between "organization that authenticated" and "repository that gets written."

### Impact Explanation
This breaks the binding "organization whose secret authenticated the webhook == repository being written to." Depending on which handler is triggered, this enables:
- Forged `push` events causing `GithubSyncJob`/deploy pipeline state changes on a victim stack (`PushHandler#process` → `stack.sync_github`).
- Forged `status` events injecting fake CI/commit statuses on a victim's commits (`StatusHandler#process` → `commit.create_status_from_github!`), which can influence Shipit's ability to consider a commit deployable/mergeable.
- Forged `pull_request`/`check_suite`/`membership` events on stacks/teams the attacker does not own.

Given Shipit's model where commit status and check state gate deploy/merge decisions, forging these events for another organization's repository can be leveraged toward an unauthorized deploy or merge decision — meeting the "unauthorized deploy, rollback, or merge" bar for Critical/High impact, without requiring any Shipit session, API token, or the victim organization's actual webhook secret.

### Likelihood Explanation
Requires the target Shipit instance to be configured for multiple GitHub organizations (a documented, supported configuration) and requires the attacker to be a legitimate admin/owner of at least one of the onboarded organizations (i.e., they know their own org's webhook secret, which they configured themselves). No access to the victim organization's secret, no Shipit user session, and no API client token is needed — only the ability to send an HTTP POST to the public webhook endpoint with a crafted body and a valid signature computed using their own known secret.

### Recommendation
After selecting the GitHub App config and verifying the signature, re-validate that the organization used for signature selection matches the actual repository/organization referenced elsewhere in the payload (e.g., assert `repository.full_name.split('/').first == repository_owner` and that this organization owns the resolved `Repository`) before dispatching to handlers. Alternatively, resolve the target `Repository` first, derive its configured organization, and require that the same organization's secret validated the signature — i.e., make the field used for authentication and the field used for the write operation the same value.

### Proof of Concept
1. Configure Shipit with two organizations, `org-a` and `org-b`, each with distinct `webhook_secret`s, as documented in `docs/setup.md` "Using Multiple Github Applications".
2. As the legitimate admin of `org-a`'s GitHub App (attacker), craft a `push` webhook JSON body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-controlled sha>",
  "repository": {
    "owner": { "login": "org-a" },
    "full_name": "org-b/victim-repo"
  }
}
```
3. Compute `X-Hub-Signature: sha1=<hmac using org-a's known webhook_secret over the raw body>`.
4. POST to `/github/webhooks` (or the configured webhook endpoint) with header `X-Github-Event: push`.
5. `WebhooksController#verify_signature` calls `Shipit.github(organization: "org-a")` and the signature validates successfully.
6. `Shipit::Webhooks.for_event('push')` dispatches to `PushHandler`, which resolves stacks via `Repository.from_github_repo_name("org-b/victim-repo")` and calls `stack.sync_github(expected_head_sha: ...)` on `org-b`'s stack — an action the attacker was never authorized to trigger, achieved purely by knowing `org-a`'s own secret.

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
