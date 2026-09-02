### Title
Cross-organization webhook forgery via mismatched signature-selection and repository-resolution fields - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which `GitHubApp` (and thus which `webhook_secret`) to verify the `X-Hub-Signature` against using `repository_owner`, taken from `params.dig('repository', 'owner', 'login')` [1](#0-0) . That value is read from the unverified JSON body before the signature is ever validated, and it is used only to pick the HMAC key [2](#0-1) . Once the signature check passes, the actual event handling never re-uses `repository_owner`; instead `Handler#stacks` resolves the target repository/stack independently from `payload.dig('repository', 'full_name')` [3](#0-2) . Because `repository.owner.login` and `repository.full_name` are two independent, attacker-controlled fields in the same JSON body, an attacker who legitimately administers *any* GitHub organization that has its own Shipit GitHub App installation (and therefore legitimately knows that org's `webhook_secret`, as documented in the multi-org setup guide) can sign a forged payload with their own org's secret while setting `repository.full_name` to a completely different, victim organization's repository.

### Finding Description
The binding that should hold is: *organization whose signature authenticated the request* == *repository whose stack is acted upon*. This binding is broken:

- `verify_signature` computes `repository_owner` from `params.dig('repository', 'owner', 'login')` and fetches `Shipit.github(organization: repository_owner)` to obtain the matching `webhook_secret`, then calls `verify_webhook_signature` [2](#0-1) .
- `GitHubApp#verify_webhook_signature` performs a straightforward HMAC-SHA1 comparison of the raw body against whichever `webhook_secret` was selected [4](#0-3) .
- The engine explicitly supports multiple GitHub Apps, one per organization, each with its own independently configured `webhook_secret`, as documented in `docs/setup.md` ("Using Multiple Github Applications") [5](#0-4) . An organization admin who installs their own GitHub App on a shared Shipit instance legitimately knows their own org's `webhook_secret`.
- Once `verify_signature` passes, `WebhooksController#create` parses the same raw JSON and dispatches it to handlers using only the event type, with no re-binding to `repository_owner` [6](#0-5) .
- `Handlers::Handler#stacks` looks up the target `Repository`/`Stack` purely from `payload.dig('repository', 'full_name')` via `Repository.from_github_repo_name` [3](#0-2) [7](#0-6) .
- `PushHandler#process` then triggers `stack.sync_github(expected_head_sha: params.after)` for any non-archived stack on the resolved repository whose branch matches the attacker-supplied `ref` [8](#0-7) .

Thus, `repository.owner.login` (used to select the signing key) and `repository.full_name` (used to select the affected stack) are never cross-checked against each other, letting a signature that is valid for organization A authorize a push/sync event for a stack that belongs to organization B.

### Impact Explanation
An attacker who legitimately controls a GitHub organization with its own Shipit GitHub App installation (and thus knows that org's `webhook_secret` by design) can forge a `push` webhook whose `repository.owner.login` points at their own org (so the signature check passes) but whose `repository.full_name` points at an arbitrary victim repository/stack hosted on the same Shipit instance. This lets the attacker enqueue a `GithubSyncJob` and drive `Stack#sync_github` for a repository they have no relationship to, forcing an out-of-band sync/deploy trigger to an attacker-chosen `expected_head_sha`. On a Shipit instance configured for continuous deployment, this can result in an unauthorized deploy of a specific commit, satisfying the "unauthorized deploy" Critical impact criterion.

### Likelihood Explanation
Any tenant/organization admin of a shared multi-org Shipit deployment (a configuration explicitly documented and supported) can carry out this attack without needing access to the victim organization's secrets, tokens, or GitHub permissions — only their own org's legitimately-known `webhook_secret` and knowledge of the target repository's `owner/name`.

### Recommendation
Bind signature verification and stack resolution to the same trusted value. After selecting `github_app` via `repository_owner`, validate that `payload.dig('repository', 'full_name')`'s owner segment matches `repository_owner` before dispatching to handlers (or resolve `repository_name` from the same verified `repository_owner`/organization context rather than trusting the independent `full_name` field), rejecting the webhook with 422 on mismatch.

### Proof of Concept
1. Attacker is the admin of GitHub organization `attacker-org`, which has its own Shipit GitHub App configured with `webhook_secret = S` per `docs/setup.md`'s multi-org instructions.
2. Attacker crafts a JSON push payload:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(S, body)>` and POSTs to `/webhooks` with `X-Github-Event: push`.
4. `verify_signature` resolves `Shipit.github(organization: 'attacker-org')`, verifies successfully against secret `S` [2](#0-1) .
5. `create` dispatches to `PushHandler`, which resolves `Repository.from_github_repo_name('victim-org/victim-repo')` and calls `sync_github` on its stacks [8](#0-7) , even though the signing organization has no relation to `victim-org`.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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
