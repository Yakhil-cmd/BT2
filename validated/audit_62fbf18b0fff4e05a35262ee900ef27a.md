### Title
Webhook HMAC signature is validated against the organization named in the payload, not the repository the event actually mutates, allowing cross-repository status/stack forgery - (File: app/controllers/shipit/webhooks_controller.rb, app/models/shipit/webhooks/handlers/handler.rb, app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`WebhooksController#verify_signature` selects which `webhook_secret` to validate the HMAC against by reading `repository.owner.login` / `organization.login` straight out of the untrusted payload, then verifies the signature over the raw body using that self-selected secret. [1](#0-0)  The handlers that actually mutate state, however, read a *different* field from the same payload (`repository.full_name` in `Handler#repository_name`, or nothing at all in `StatusHandler`) to decide which `Repository`/`Stack`/`Commit` to act on. [2](#0-1) [3](#0-2)  Because Shipit supports multiple independently-configured GitHub organizations sharing one instance (each with its own `webhook_secret`), an attacker who administers any one of those configured organizations can sign a payload with their own known secret while pointing the acted-upon fields at a completely different, victim organization's repository/commit. [4](#0-3) 

### Finding Description
The signature check and the state-mutation logic bind on two different fields of the same JSON body:

1. `WebhooksController#repository_owner` picks the org used to fetch the `GithubApp`/secret:
```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [5](#0-4) 

`verify_signature` then does `Shipit.github(organization: repository_owner)` and HMAC-verifies the *entire raw body* against that org's `webhook_secret`. [6](#0-5) 

2. `Handler#repository_name`, used by e.g. `PushHandler` to find the `Stack` to mutate, reads a *different* key (`repository.full_name`) from the very same body:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [2](#0-1) 

3. `StatusHandler#process` does not consult repository ownership at all — it looks up commits globally by SHA and writes a status onto whatever commit matches, in whatever stack that commit belongs to:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [3](#0-2) 

Because the attacker fully controls the raw JSON body that is both signed and interpreted, they can set `repository.owner.login`/`organization.login` to their own organization (so `verify_signature` fetches and checks against their own, legitimately-known `webhook_secret`) while independently setting `repository.full_name` (for `PushHandler`, `pull_request/*Handler`, etc.) or `sha` (for `StatusHandler`) to reference a victim repository/commit that has nothing to do with the authenticating organization. The signature is fully valid — it was computed by the attacker with their own secret over a body they control — but the handler acts on a target that was never covered by the org-selection logic. This is the exact equality break called out in scope: "an organization that authenticated versus the repository that is written."

### Impact Explanation
This lets any organization/repository administrator who is configured as *one of the (possibly many) GitHub organizations wired into a shared Shipit instance* forge webhook events attributed to *any other* organization's tracked repositories/commits, without ever needing that victim organization's `webhook_secret`:
- Forged `status` events can attach arbitrary CI/check state (`state`, `context`, `target_url`) to any known commit SHA of a victim stack via `Commit#create_status_from_github!`, since `StatusHandler` performs no repository-scoping check at all. [3](#0-2)  Commit statuses gate whether a commit is considered deployable in Shipit's merge/deploy pipeline, so this can be used to make an otherwise-blocked commit appear CI-green and eligible for deploy.
- Forged `push`/`pull_request` events can cause `Stack#sync_github` to run or a victim's stack to be archived, because the only binding used to pick the target stack (`repository.full_name`) is never cross-checked against the organization whose secret validated the signature. [7](#0-6) 

This satisfies the required "unauthorized deploy" / cross-repository-write impact category.

### Likelihood Explanation
The precondition is realistic and unprivileged with respect to the victim: the attacker only needs to control (or be an admin of) *any single* GitHub organization that this Shipit deployment has configured — a normal, documented multi-org setup (`config/secrets.development.shopify.yml` shows two independent orgs, each with its own `webhook_secret`, sharing one Shipit app). [4](#0-3)  No access to the victim organization, no GitHub session, and no privileged Shipit account is required — only knowledge of a public commit SHA or repository full name belonging to the victim, both of which are visible on GitHub. This is a design flaw in field binding, not a cryptographic break, matching the report's "unchecked/uncovered field" bug class exactly.

### Recommendation
Bind the signature-selection organization and the state-mutation target to the same, single field, and enforce that equality explicitly:
- Have `WebhooksController` resolve and pass down the authenticated organization (the one whose secret verified successfully), and have every `Handler` (especially `StatusHandler`) verify that the resource it is about to mutate (`Commit#stack#repository#owner`, `Repository#owner`) matches that authenticated organization before making any change.
- Scope `StatusHandler#process` by repository (e.g., join through `payload.dig('repository','full_name')` and require it to match the commit's stack's repository) instead of an unscoped `Commit.where(sha: ...)`.
- Reject webhooks where `repository.owner.login`/`organization.login` and `repository.full_name`'s owner segment disagree.

### Proof of Concept
1. Attacker administers `attacker-org`, which is configured in this Shipit instance with its own `webhook_secret` (`S_attacker`), per the standard multi-org config shown in `config/secrets.development.shopify.yml`.
2. Attacker crafts a `status` event JSON body:
```json
{
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "attacker-org/attacker-repo" },
  "organization": { "login": "attacker-org" },
  "sha": "<victim commit sha>",
  "state": "success",
  "context": "ci/required-check",
  "created_at": "..."
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC-SHA1(S_attacker, body)` — a signature they can legitimately produce since `S_attacker` is their own secret.
4. `POST /webhooks` with `X-Github-Event: status`. `WebhooksController#repository_owner` resolves to `attacker-org`, `Shipit.github(organization: 'attacker-org')` returns the attacker's own `GithubApp`, and `verify_webhook_signature` succeeds because the signature matches `S_attacker` over the attacker-controlled body. [6](#0-5) 
5. `StatusHandler#process` runs `Commit.where(sha: params.sha)`, finds the victim's commit (SHA is public), and calls `commit.create_status_from_github!(params)`, writing a forged "success" status onto a commit the attacker's organization has no relationship to. [3](#0-2)

### Citations

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
