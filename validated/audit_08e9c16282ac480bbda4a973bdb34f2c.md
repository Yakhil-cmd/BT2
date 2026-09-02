### Title
Webhook signature verified against `repository.owner.login`, but the event is applied to `repository.full_name` — cross-organization forgery of webhook events - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects the GitHub App/webhook secret used to validate the HMAC signature from `repository.owner.login` (or `organization.login`) found inside the very payload being verified. Once the signature check passes, the raw JSON body is handed unmodified to `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }`, and every handler resolves the target stack via `repository.full_name` (`app/models/shipit/webhooks/handlers/handler.rb#repository_name`/`#stacks`), a completely independent field of the same payload. Nothing forces `repository.full_name` to belong to the same organization as `repository.owner.login`.

### Finding Description
- `verify_signature` in `app/controllers/shipit/webhooks_controller.rb:24-49` computes:
  ```ruby
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
  ```
  where `repository_owner` (`app/controllers/shipit/webhooks_controller.rb:59-62`) is `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')`. [1](#0-0) [2](#0-1) 

- The signature itself is a plain HMAC over the whole raw body using the secret configured for that organization (`lib/shipit/github_app.rb#verify_webhook_signature`), so any valid signer for organization `A` can produce a *validly signed* payload whose body content, including `repository.full_name`, is arbitrary. [3](#0-2) 

- After verification, the controller dispatches the parsed body to handlers unchanged:
  ```ruby
  params = JSON.parse(request.raw_post)
  Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }
  ``` [4](#0-3) 

- Every handler (`Handler` base class) resolves the affected stack(s) from `repository.full_name`, not from `repository.owner.login`:
  ```ruby
  def stacks
    @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
  end

  def repository_name
    payload.dig('repository', 'full_name')
  end
  ``` [5](#0-4) 

- `Repository.from_github_repo_name` simply splits the string on `/` and looks up any repository/stack owned by anyone in the datastore, with no cross-check against the organization whose secret validated the request:
  ```ruby
  def self.from_github_repo_name(github_repo_name)
    repo_owner, repo_name = github_repo_name.downcase.split('/')
    find_by(owner: repo_owner, name: repo_name)
  end
  ``` [6](#0-5) 

This breaks the trust binding: **organization that authenticated the request (`repository.owner.login`, tied to the verified HMAC secret) ≠ repository that is written to (`repository.full_name`, used by every handler to locate the stack)**. Since the whole JSON body — including both fields — is under a single attacker-controlled organization's signature, nothing stops the two fields from diverging.

### Impact Explanation
In a multi-tenant Shipit deployment (`docs/setup.md` "Using Multiple GitHub Applications" section documents this configuration explicitly), each onboarded GitHub organization has its own `webhook_secret`, which is visible to that organization's own GitHub App administrators (it is the value they configured on GitHub's side). Any such organization admin can:
1. Craft a JSON payload where `repository.owner.login` = their own org (so `Shipit.github(organization: ...)` resolves to the secret they know), but `repository.full_name` = `"other-org/other-repo"` — a stack belonging to a different tenant.
2. Sign the payload with their own valid `webhook_secret` and POST it to `/webhooks`.
3. The signature check passes because it only verifies "this body was HMAC'd with organization A's secret" — it says nothing about which repository the body claims to describe.
4. The dispatched handler (e.g. `push_handler.rb`, `status_handler.rb`, `check_suite_handler.rb`) resolves the target stack via `repository.full_name` and acts on the victim org's stack: enqueuing `GithubSyncJob`, creating commit `Status` rows that gate CI/deployability, or triggering `RefreshCheckRunsJob`.

Depending on the handler, this can influence what commits are considered deployable/CI-green for a completely unrelated tenant's stack, which is a cross-tenant integrity break reachable purely with knowledge of one's own organization's webhook secret — no Shipit session, API token, or GitHub write access to the victim repository is required.

### Likelihood Explanation
Requires only being an administrator (or having leaked access to the webhook secret) of any one organization already onboarded to the same multi-tenant Shipit instance — a low bar in shared/hosted deployments, and exactly the deployment mode the engine's own documentation describes and supports (`docs/setup.md`, "Using Multiple Github Applications"). No other credential, GitHub write access, or session is needed. [7](#0-6) 

### Recommendation
After verifying the HMAC signature, cross-check that the resolved `repository_owner` used for secret lookup matches the owner embedded in `repository.full_name` (and `organization.login` when present) before allowing any handler to act on the payload; reject the request if they diverge.

### Proof of Concept
1. Attacker administers Org `A`, legitimately onboarded to a multi-tenant Shipit instance, and knows `A`'s `webhook_secret` (visible in their own GitHub App/webhook settings).
2. Attacker builds a `push` payload:
   ```json
   {
     "repository": { "owner": {"login": "A"}, "full_name": "victim-org/victim-repo" },
     "ref": "refs/heads/main",
     "after": "<attacker-chosen sha>"
   }
   ```
3. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(A_secret, body)>` and POSTs to `/webhooks` with `X-Github-Event: push`.
4. `verify_signature` resolves `repository_owner` = `"A"`, fetches `A`'s app/secret, and the HMAC check passes.
5. `PushHandler` (via `Handler#stacks`/`#repository_name`) resolves `Repository.from_github_repo_name("victim-org/victim-repo")` and enqueues `GithubSyncJob` against `victim-org/victim-repo`'s stack — an org the attacker never authenticated for.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** docs/setup.md (L181-209)
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
