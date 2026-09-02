### Title
Webhook signature verification keys on `repository.owner.login` while every handler acts on `repository.full_name`, letting a holder of one configured organization's `webhook_secret` forge deliveries that write into another organization's stacks - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which per-organization `webhook_secret` to validate the HMAC against using an *unverified* payload field, `repository.owner.login` (falling back to `organization.login`). Once the signature check passes, every `Shipit::Webhooks::Handlers::Handler` subclass resolves the target `Repository`/`Stack` to act on using a *different* unverified payload field, `repository.full_name` [1](#0-0) . Nothing ties these two fields together, so the field that gates cryptographic trust is not the field that determines which repository's data gets mutated.

### Finding Description
`verify_signature` computes:

```
github_app = Shipit.github(organization: repository_owner)
verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
```
where `repository_owner = params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` [2](#0-1) .

`GitHubApp#verify_webhook_signature` performs a constant-time HMAC comparison keyed on that organization's configured `webhook_secret` [3](#0-2) . Shipit supports multiple, independently configured GitHub Apps/organizations, each with its own `webhook_secret` in `secrets.yml` [4](#0-3) , and the docs confirm each org's secret is set independently at App-creation time [5](#0-4) .

After verification, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` dispatches the raw, attacker-controlled JSON to handlers such as `PushHandler`, `StatusHandler`, PR handlers, etc. [6](#0-5) . Every one of them locates the target repository via `Handler#repository_name`, which reads `payload.dig('repository', 'full_name')` and looks it up with `Repository.from_github_repo_name` [1](#0-0) , [7](#0-6) . `PushHandler#process` then calls `stack.sync_github(expected_head_sha: ...)` on whatever stacks match that repository/branch [8](#0-7) .

Because the field used to pick the verification key (`repository.owner.login`) and the field used to pick the acted-upon repository (`repository.full_name`) both come from the same attacker-suppliable JSON body and are never cross-checked against each other, an entity that legitimately possesses the `webhook_secret` for organization A (i.e., they administer/own the GitHub App configured for org A in Shipit's `secrets.yml`) can compute a valid HMAC over a crafted payload whose `repository.owner.login` is `"orgA"` (so the correct secret is selected and verification succeeds) but whose `repository.full_name` is `"orgB/victim-repo"`. The signature check passes because it never inspects `full_name`, yet the handler acts on org B's `Stack` — e.g., forcing a `sync_github`/status update flow, or (via other handlers) manipulating PR/label/merge state — for a repository the attacker was never authorized to touch. This is the binding-break analog to the `_priceA`/`_priceB` mismatch: the value verified is not the value used downstream.

### Impact Explanation
This produces a cross-repository write: a party trusted only for organization A's webhook channel can inject events that Shipit will process as authentic for organization B's `Stack`/`Repository`, mutating commit/status/PR state or driving deploy-relevant sync jobs (`GithubSyncJob`) tied to a repository they have no authorization over. Per the assessment's impact rubric, "cross-repository writes" is a Critical-tier outcome.

### Likelihood Explanation
Exploitability depends on the deployment having more than one organization/App configured in `secrets.yml` (a documented, supported configuration) and the attacker being the legitimate holder of one organization's `webhook_secret` (i.e., they created/administer that GitHub App entry) — this is exactly an "organization that authenticated versus the repository that is written" boundary break called out as in-scope. No repository write access, session, or `ApiClient` token on the victim side is required; only knowledge of one configured secret and the ability to send an arbitrary HTTP POST to `/webhooks` with a matching `X-Hub-Signature`.

### Recommendation
Bind the verification key to the same field the handler uses for the mutation, and validate consistency between them: derive `repository_owner` from `repository.full_name` (the same field consumed in `Handler#repository_name`) rather than from `repository.owner.login`/`organization.login`, or explicitly assert `repository.full_name.split('/').first == repository.owner.login` before dispatching. More robustly, resolve the target `Repository` first, confirm its `owner` matches the organization whose secret validated the signature, and reject the webhook otherwise.

### Proof of Concept
1. Shipit is configured with two GitHub App entries in `secrets.yml`: `orgA` (attacker-controlled App, attacker knows its `webhook_secret`) and `orgB` (victim org, has a `Stack` tracking `orgB/victim-repo`).
2. Attacker crafts a JSON payload:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "orgA" },
    "full_name": "orgB/victim-repo"
  }
}
```
3. Attacker computes `sha1=HMAC-SHA1(webhook_secret_orgA, raw_body)` and sends it as `X-Hub-Signature` with `X-Github-Event: push` to `/webhooks`.
4. `verify_signature` resolves `repository_owner` to `"orgA"`, fetches `Shipit.github(organization: "orgA")`, and the HMAC matches — the request is accepted [9](#0-8) .
5. `Shipit::Webhooks.for_event('push')` invokes `PushHandler`, whose `Handler#repository_name` reads `full_name` = `"orgB/victim-repo"`, resolves org B's `Repository`/`Stack`, and calls `stack.sync_github(expected_head_sha: params.after)` — acting on org B's stack using a signature that was only ever validated against org A's secret [8](#0-7) , [7](#0-6) .

### Citations

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** docs/setup.md (L119-119)
```markdown
**`github.webhook_secret`** If you've set a webhook secret during the App creating, you should copy it here.
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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
