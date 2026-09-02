### Title
Webhook signature is verified against `repository.owner.login`, but the handler resolves the target Repository/Stack from `repository.full_name` — allowing cross-organization webhook forgery in multi-GitHub-App deployments - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App (and therefore which `webhook_secret`) to validate an inbound webhook against using `repository_owner`, computed from `params.dig('repository', 'owner', 'login')` (or `organization.login`) [1](#0-0) [2](#0-1) . However, `Webhooks::Handlers::Handler#repository_name`, used by handlers such as `PushHandler` to resolve the local `Repository`/`Stack` that will actually be acted upon, reads a *different* field of the same attacker-controlled JSON body: `payload.dig('repository', 'full_name')` [3](#0-2) , which is then split into owner/name and looked up directly in the database via `Repository.from_github_repo_name` [4](#0-3) . The HMAC signature only proves the payload was signed with the secret belonging to the App configured for `repository.owner.login`; it does not bind that secret to `repository.full_name`. In a supported multi-organization deployment — explicitly documented in `docs/setup.md` ("Using Multiple Github Applications") where each GitHub org has its own `app_id`/`webhook_secret` keyed under `github:` [5](#0-4)  — an attacker who legitimately owns one configured (but unprivileged) org can sign a forged payload with their own known `webhook_secret` while setting `repository.full_name` to a victim org/repository that is also tracked by the same Shipit instance.

### Finding Description
- Verification path: `Shipit.github(organization: repository_owner)` fetches the App config for whatever organization login appears in the payload, then `verify_webhook_signature` checks the `X-Hub-Signature` HMAC against that org's secret [1](#0-0) .
- Action path: `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` dispatches the parsed JSON to handlers [6](#0-5) , and `PushHandler#process` uses `stacks` (backed by `repository_name` → `full_name`) to find matching `Stack`s and calls `stack.sync_github(expected_head_sha: params.after)` with an attacker-supplied SHA [7](#0-6) .
- Because `repository.owner.login` (used for signature/App selection) and `repository.full_name` (used to pick the DB row acted upon) are independent, attacker-controlled fields of the same JSON body, a forged payload can pass signature verification under org A's secret while the effectual repository/stack resolved is org B's.
- This breaks the required binding: "an organization that authenticated versus the repository that is written."

### Impact Explanation
An attacker who is a legitimate but unprivileged member/owner of one GitHub organization configured on a shared, multi-org Shipit instance can forge push/status/check_suite webhooks that are processed as if they originated from a different organization's repository that they have no access to. For push events this triggers `stack.sync_github(expected_head_sha: <attacker-chosen sha>)`, i.e. a cross-repository write into another org's `Stack`/`Commit` records and a forced GitHub sync using an attacker-chosen head SHA, potentially cascading into a downstream unauthorized deploy on stacks with continuous deployment enabled. This satisfies the "cross-repository writes" / "unauthorized deploy" High/Critical impact criteria.

### Likelihood Explanation
Requires the target Shipit instance to be configured with more than one GitHub App/organization (a supported, documented configuration, not a misconfiguration of the host app), and requires the attacker to control one of those configured (but otherwise unprivileged) organizations — enough to know that org's own `webhook_secret`. No access to the victim org, no `ApiClient` token, no session, and no GitHub App private key is needed.

### Recommendation
Bind the verified organization to the repository actually acted upon: derive `repository_name`/stack lookup consistently from the same field used for signature-app selection (e.g., verify that `repository.full_name`'s owner segment equals `repository.owner.login`/`organization.login` before dispatching to handlers), or reject payloads where these disagree.

### Proof of Concept
Not independently executed; based on static code review of `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/handler.rb`, `app/models/shipit/webhooks/handlers/push_handler.rb`, and `app/models/shipit/repository.rb`, plus the documented multi-org configuration in `docs/setup.md`. Conceptually:
1. Configure Shipit (per docs) with two orgs, `attacker-org` and `victim-org`, each with its own `webhook_secret`.
2. Attacker crafts a `push` webhook JSON body: `{"repository": {"owner": {"login": "attacker-org"}, "full_name": "victim-org/victim-repo"}, "ref": "refs/heads/<branch>", "after": "<attacker-chosen sha>"}`.
3. Attacker signs it with `attacker-org`'s known `webhook_secret` and sends it to `/webhooks`.
4. `verify_signature` selects `attacker-org`'s App/secret via `repository_owner` and succeeds.
5. `PushHandler` resolves the `Stack` via `full_name` = `victim-org/victim-repo`, calling `sync_github(expected_head_sha: "<attacker-chosen sha>")` on a stack the attacker does not own.

I was unable to execute this end-to-end in a live environment or inspect `Stack#sync_github`/`GithubSyncJob` internals in full within the available iterations, so the downstream severity (whether sync alone can force a deploy, versus only updating cached commit state) could not be fully confirmed from the code shown; this should be validated further before treating the downstream impact as confirmed "unauthorized deploy" rather than "unauthorized data/state write."

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-30)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified
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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
