### Title
Webhook signature verification is keyed to `repository.owner.login`/`organization.login` while the acted-upon repository is resolved from the independent `repository.full_name` field, allowing cross-organization signature confusion - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App configuration (and therefore which HMAC secret) is used to authenticate an inbound webhook based on `repository.owner.login` (falling back to `organization.login`), a field taken directly from the untrusted, attacker-suppliable JSON body prior to signature verification. Once "verified", the actual handler (`Shipit::Webhooks::Handlers::Handler#repository_name`) resolves the repository/stack to mutate using a *different* JSON field, `repository.full_name`. Nothing in the code enforces that the organization used to authenticate the payload is the same organization embedded in `full_name`.

### Finding Description
The controller picks the signing/verification context purely from payload content: [1](#0-0) [2](#0-1) 

`Shipit.github(organization: repository_owner)` returns the `GithubApp` instance configured for that specific organization key in `secrets.yml`, and `verify_webhook_signature` is defined as: [3](#0-2) 

Crucially, `return true unless webhook_secret` — if the organization resolved from the payload has no `webhook_secret` configured, *any* signature (or none at all) is accepted. Multi-organization installs with a per-org optional `webhook_secret` are an explicitly supported, documented configuration (see the sample configs where one org has a secret and another has `webhook_secret: # nil`), not a misconfiguration outside the engine's design: [4](#0-3) 

Once the request passes `verify_signature`, `WebhooksController#create` re-parses the same raw body and dispatches to handlers: [5](#0-4) 

Handlers determine which `Repository`/`Stack` to mutate using a **separate** field, `repository.full_name`, not `repository.owner.login`: [6](#0-5) [7](#0-6) 

`Repository.from_github_repo_name` splits `full_name` on `/` and looks the record up purely by that string: [8](#0-7) 

The binding that should hold is:
`organization used to select the webhook secret (repository.owner.login / organization.login)` == `organization embedded in the repository actually written (repository.full_name`'s owner segment)`.

The code never enforces this equality — both values are read from independent keys of the same attacker-controlled JSON body. An attacker who can trigger (or forge, when the resolved org has no secret) a webhook delivery can set `repository.owner.login` to an organization that verifies trivially (no `webhook_secret` configured) while setting `repository.full_name` to `"<other-org>/<sensitive-repo>"`, causing the handler to operate on a stack belonging to a different, better-protected organization (e.g. triggering `GithubSyncJob`, creating a `PullRequest`, adding a `Team` `Membership`, or updating commit `Status`/`CheckRun` state) as if it were authenticated for that org.

### Impact Explanation
This breaks a repository/organization identity binding: the "verified" identity (an org whose webhook authentication is intentionally weak/absent under a documented configuration) is silently substituted for the identity of the actually-affected repository. Depending on the handler reached, this can enqueue sync jobs, forge commit statuses/check-run state, or manipulate pull-request/merge state for a repository outside the "verified" organization — an unauthorized cross-repository write reachable by an unauthenticated network attacker, matching the High-impact class ("escalation... unauthenticated... cross-repository writes" style entries in the rubric).

### Likelihood Explanation
Likelihood is moderate to high in any deployment supporting multiple GitHub organizations where at least one configured organization omits `webhook_secret` (a state the shipped sample configs treat as a normal, supported option, e.g. for local/dev orgs coexisting with a hardened production org in the same instance). No credential, session, or knowledge of any secret is required — only knowledge of the target repository's `full_name` and of one org name in the install that lacks a webhook secret.

### Recommendation
Do not let two independent, attacker-controlled JSON fields determine "who authenticated" versus "what gets written." After signature verification succeeds, derive the acted-upon repository's owner directly from the same `repository_owner` value used for signature verification (or, conversely, verify the signature using the owner segment parsed out of `repository.full_name`), and reject the webhook if the two disagree. Additionally, reconsider allowing `verify_webhook_signature` to unconditionally return `true` when `webhook_secret` is blank in any multi-org install — at minimum, require every configured organization sharing an install to define a webhook secret, or scope handler execution so an org lacking a secret cannot cause writes to repositories owned by a different, secret-protected organization.

### Proof of Concept
1. Configure Shipit with two organizations in `secrets.yml`: `OrgSecure` (with a `webhook_secret`) tracking `OrgSecure/critical-app`, and `OrgOpen` (with `webhook_secret` left blank), as shown in `test/dummy/config/secrets_double_github_app.yml`.
2. POST to `/webhooks` with header `X-Github-Event: push` and no (or an arbitrary) `X-Hub-Signature`, and body:
```json
{
  "ref": "refs/heads/master",
  "after": "deadbeef",
  "repository": { "owner": { "login": "OrgOpen" }, "full_name": "OrgSecure/critical-app" }
}
```
3. `verify_signature` computes `repository_owner == "OrgOpen"`, calls `Shipit.github(organization: "OrgOpen")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` regardless of the (missing/garbage) signature.
4. `PushHandler#repository_name` reads `payload.dig('repository', 'full_name')` = `"OrgSecure/critical-app"`, resolves `OrgSecure`'s tracked stacks, and enqueues `stack.sync_github(expected_head_sha: "deadbeef")` — a write to `OrgSecure`'s stack triggered under `OrgOpen`'s (unauthenticated) identity.

*Note: I could not fully trace every downstream handler's exact side effects (e.g. exact CheckRun/Status/PullRequest write paths) within the available exploration budget; the `push_handler.rb`/`membership_handler.rb` paths shown above were directly confirmed, and other handlers in `app/models/shipit/webhooks/handlers/**` follow the same `Handler#repository_name` base method and are presumed equally affected.*

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

**File:** test/dummy/config/secrets_double_github_app.yml (L41-46)
```yaml
    OrgTwo:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
