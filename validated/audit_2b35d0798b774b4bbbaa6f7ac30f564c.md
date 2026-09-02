### Title
Webhook signature is verified against `repository.owner.login` while the repository actually acted upon is taken from the unverified `repository.full_name` field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
Shipit supports hosting multiple GitHub organizations behind one instance, each with its own `webhook_secret` [1](#0-0) . `WebhooksController#verify_signature` picks which organization's secret to validate the HMAC signature with by reading `repository.owner.login` (or `organization.login`) out of the **unauthenticated** JSON body itself, before the signature has been checked [2](#0-1) . Every webhook handler, however, resolves the stack/repository it actually mutates from a *different* field of that same body — `repository.full_name` — via `Handler#repository_name`/`Handler#stacks` [3](#0-2) , and `PushHandler#process` acts on whatever stacks match that repository [4](#0-3) .

### Finding Description
The binding that should hold is: **organization whose secret authenticated the request == owner of the repository the handler writes to**. Nothing enforces this equality:

- `repository_owner` (used to select the `GithubApp`/secret for `verify_webhook_signature`) is read from `repository.owner.login` [5](#0-4) .
- The repository actually looked up and mutated by the handler is read from `repository.full_name` via `Repository.from_github_repo_name` [6](#0-5) .

Because the entire raw POST body is attacker-controlled up to producing a valid signature, and the signature-selection field (`repository.owner.login`/`organization.login`) is independent of the mutation-target field (`repository.full_name`), an attacker who legitimately administers *any* GitHub organization configured in this Shipit instance (and therefore knows that organization's `webhook_secret`, which they themselves set when installing their GitHub App) can craft a body where `repository.owner.login` equals their own organization (so the signature check passes with the secret only they know), while `repository.full_name` names an arbitrary victim repository/stack hosted on the same instance. Every handler that resolves stacks via `Handler#stacks`/`repository_name` — `PushHandler`, `StatusHandler`, `CheckSuiteHandler`, the `PullRequest::*` handlers — will then operate on the victim stack.

For `PushHandler`, this lets the attacker enqueue `Stack#sync_github(expected_head_sha: ...)` → `GithubSyncJob` for a stack they don't own [4](#0-3) , forcing resyncs/spec re-caches, and — combined with the `status` and `check_suite` handlers that key off `sha`/`repository.full_name` rather than the authenticated organization — allows commit CI status objects on the victim's stack to be created/mutated using only the attacker's own webhook secret.

### Impact Explanation
This breaks the "unauthorized deploy/rollback/merge" and "authentication bypass" boundary: a party that is only entitled to send authenticated webhooks for their own organization's repositories can cause Shipit to write state (sync jobs, commit statuses that feed CI-gating and continuous-delivery eligibility) for a completely different organization's stack, without ever possessing that organization's `webhook_secret`, GitHub App credentials, or Shipit API token. Depending on which handler is reached, this can influence whether continuous deployment triggers a real deploy of the victim stack (since CI/status data drives `deployable?`/`trigger_continuous_delivery`), satisfying the High/Critical bar for "unauthorized deploy" or "escalation" style impact.

### Likelihood Explanation
Requires only: (1) the target Shipit instance to host more than one GitHub organization (a documented, supported configuration), and (2) the attacker to control (or be the admin of) at least one of those organizations' GitHub App installs so they know its `webhook_secret`. No repository write access, no Shipit `ApiClient` token, and no access to the victim's secrets are needed — only a raw HTTP POST to the public `/webhooks` endpoint with a crafted body. This is a plausible, low-effort attack path for any multi-tenant Shipit deployment.

### Recommendation
After signature verification succeeds, re-derive the authenticated organization and assert that every repository referenced by the handler (`repository.full_name`, and any `organization.login` used inside handler `process` methods) belongs to that same authenticated organization before performing any lookup or mutation — i.e., make `repository_owner` and the value handlers use to resolve `stacks`/`Repository.from_github_repo_name` provably the same field, or explicitly cross-check `full_name.split('/').first == repository_owner` before dispatching to handlers.

### Proof of Concept
1. Attacker administers `attacker-org` on the shared Shipit instance and knows `attacker-org`'s `webhook_secret` (they configured it themselves in their own GitHub App settings).
2. Attacker POSTs to `/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/production",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature` using `attacker-org`'s known `webhook_secret` over this exact body.
4. `WebhooksController#verify_signature` resolves `repository_owner` = `"attacker-org"`, fetches `Shipit.github(organization: "attacker-org")`, and the signature validates successfully [7](#0-6) .
5. `PushHandler#process` is invoked with the same body; `Handler#repository_name` reads `"victim-org/victim-repo"` and `Handler#stacks` finds the victim's real stacks, enqueuing `GithubSyncJob`/status updates against them [6](#0-5) [4](#0-3)  — despite the attacker never possessing any credential belonging to `victim-org`.

### Citations

**File:** docs/setup.md (L182-209)
```markdown
### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

```yml
production:
  github:
    somegithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
    someothergithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
```
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
