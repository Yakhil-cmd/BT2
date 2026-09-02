### Title
Webhook signature verified against `repository.owner.login` while stack-mutating handlers act on `repository.full_name` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/`webhook_secret` to use for HMAC verification based on `params.dig('repository', 'owner', 'login')`, but the handlers invoked afterwards (e.g. `PushHandler`) resolve the target `Repository`/`Stack` using a different field of the same JSON body: `payload.dig('repository', 'full_name')`. These two fields are never cross-checked, so the "organization that authenticated" and the "repository that is written" are not the same binding.

### Finding Description
`verify_signature` computes `repository_owner` from the payload and fetches that organization's `GitHubApp`/secret to validate `X-Hub-Signature`: [1](#0-0) [2](#0-1) 

Once the signature is accepted, `create` hands the *entire raw payload* to registered handlers unchanged: [3](#0-2) 

`Handler#stacks`/`#repository_name`, used by `PushHandler`, resolve the target repository from a **different** field, `repository.full_name`: [4](#0-3) 

`Repository.from_github_repo_name` simply splits that string on `/`: [5](#0-4) 

`PushHandler#process` then enqueues sync work for every matching stack using an attacker-influenced `expected_head_sha`: [6](#0-5) 

In a genuine GitHub-originated payload, `repository.owner.login` and the owner segment of `repository.full_name` always refer to the same repository, so this discrepancy is invisible under normal operation. But nothing in the engine enforces that equality. In a multi-organization Shipit deployment (`config/secrets*.yml` supports a `github:` map keyed by organization, each with its own `webhook_secret` — see `test/dummy/config/secrets_double_github_app.yml`), an administrator of Organization A knows Organization A's `webhook_secret` (they configured it themselves in their own GitHub App settings) but has no authorization over Organization B's repositories/stacks.

That administrator can craft an arbitrary webhook JSON body with:
- `repository.owner.login = "OrgA"` (so `verify_signature` looks up and validates against Organization A's `webhook_secret`, which the attacker legitimately possesses)
- `repository.full_name = "OrgB/some-repo"` (so the handler resolves and acts on Organization B's `Stack`)

The equality that should hold — `authenticated_organization == acted_upon_repository.owner` — is broken:
- Before the attack: `repository_owner` (used to select the signing secret) and `repository_name`'s owner (used to select the target `Repository`) are always identical for genuine GitHub deliveries.
- After the attacker's crafted request: `repository_owner = "OrgA"` (attacker's own org, used only to pass the HMAC check) while `repository_name = "OrgB/some-repo"` (a foreign org's stack, actually mutated).

### Impact Explanation
This lets an attacker who legitimately controls one onboarded GitHub organization's webhook secret forge signed webhook deliveries that are processed as if they originated from a *different* organization's repository. Via `PushHandler`, this reaches `Stack#sync_github` → `GithubSyncJob`, which fetches commits from GitHub using that stack's own GitHub App credentials and appends attacker-chosen `expected_head_sha` values into the target stack's commit history, which can trigger continuous-delivery deploys of arbitrary/misleading state for a repository the attacker does not own. Other handlers keyed the same way (e.g. `status`, `check_suite`) are similarly exposed, since none of them validate `repository.owner.login` against `repository.full_name`. This crosses the "cross-repository writes" / "unauthorized deploy" bar for High/Critical impact defined by the scope rules, since it lets one authenticated organization mutate another organization's stack state and potentially trigger deploys.

### Likelihood Explanation
Exploitation requires the attacker to control at least one organization that is legitimately configured/onboarded with its own `webhook_secret` in the multi-org `github:` configuration (a scenario explicitly supported and documented, e.g. `secrets_double_github_app.yml`) — no repository write access, no `ApiClient` token, and no compromise of Organization B is needed. The attacker only needs to send one crafted HTTP POST to `/webhooks` with a body they self-sign using their own known secret. This is a realistic scenario for any Shipit instance shared across multiple organizations/tenants.

### Recommendation
In `WebhooksController#verify_signature` (or in `Shipit::Webhooks::Handlers::Handler`), enforce that the organization used to select the webhook secret is the same organization embedded in `repository.full_name` (and `organization.login`, if present) before dispatching to handlers — reject the webhook (422) on mismatch. Consider deriving the signing organization solely from a trusted server-side mapping (e.g., stack lookup) rather than trusting attacker-controlled JSON fields for secret selection.

### Proof of Concept
1. Configure Shipit with two GitHub Apps/organizations, `OrgA` and `OrgB`, each with distinct `webhook_secret`s (as supported by `config/secrets*.yml`, e.g. `test/dummy/config/secrets_double_github_app.yml`).
2. As the administrator of `OrgA` (who legitimately knows `OrgA`'s `webhook_secret` from the GitHub App settings), craft a push payload:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "owner": { "login": "OrgA" },
    "full_name": "OrgB/victim-repo"
  }
}
```
3. Compute `X-Hub-Signature: sha1=<hmac_sha1(OrgA_webhook_secret, body)>` and POST it to `/webhooks` with `X-Github-Event: push`.
4. `verify_signature` resolves `Shipit.github(organization: "OrgA")` (from `repository.owner.login`) and successfully verifies the signature using `OrgA`'s secret: [7](#0-6) 
5. `create` dispatches to `PushHandler`, which resolves `stacks` via `payload.dig('repository', 'full_name')` = `"OrgB/victim-repo"`: [4](#0-3)  and enqueues `sync_github(expected_head_sha: "<attacker-chosen-sha>")` against `OrgB`'s stack, despite the attacker never having been authorized for `OrgB`.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
