### Title
Cross-organization webhook forgery via per-organization `webhook_secret` bypass — ([File: `app/controllers/shipit/webhooks_controller.rb`])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's secret to verify a webhook against using `repository_owner` (`repository.owner.login`, falling back to `organization.login`), while `Webhooks::Handlers::Handler#stacks` resolves the actual target repository/stack from a completely different, independently-controlled payload field: `repository.full_name`. `GitHubApp#verify_webhook_signature` also returns `true` unconditionally when the selected organization's `webhook_secret` is blank. Together these two facts let an attacker who can produce a request for an organization that has *no* `webhook_secret` configured (a supported, documented configuration state) freely choose the value of `repository.full_name` to point at a stack/repository belonging to a *different*, properly-secured organization, and have it processed as authentic.

### Finding Description
In a multi-organization Shipit deployment (`docs/setup.md` "Using Multiple Github Applications"), each org has its own `github_app.webhook_secret`, and it is explicitly documented/allowed for `webhook_secret` to be left blank (`config/secrets.development.example.yml:11` `webhook_secret: # nil`).

Verification flow: [1](#0-0) 

`repository_owner` is derived like this: [2](#0-1) 

Signature check itself: [3](#0-2) 

Note the `return true unless webhook_secret` — if the organization picked via `repository_owner` has no secret configured, **any** request is treated as verified, regardless of signature contents.

Once "verified," the actual handler resolves the target stack using a *different* payload field, `repository.full_name`, not `repository.owner.login`: [4](#0-3) [5](#0-4) 

Because `repository.owner.login` (used for auth) and `repository.full_name` (used for the write target) are two separate fields in the same attacker-supplied JSON body, and the auth check is skippable for any org without a secret, an attacker can craft:
```json
{
  "repository": {
    "owner": { "login": "org-without-secret" },
    "full_name": "victim-org/victim-repo"
  },
  ...
}
```
This authenticates against `org-without-secret`'s (missing) secret — trivially true — while the handler acts on `victim-org/victim-repo`'s stacks. This breaks the equality that should hold: `organization authenticated == organization written`.

### Impact Explanation
This allows unauthenticated forgery of any webhook event type toward a stack belonging to a different, correctly-configured organization, as long as at least one organization in the same Shipit instance has a blank `webhook_secret`. Concretely reachable, unauthenticated writes include:
- Fake `push` events triggering `GithubSyncJob` for a victim stack.
- Fake `status` events injecting commit `Status` records (`StatusHandler`) that affect `Commit#deployable?`/blocking status, potentially making an otherwise-non-deployable commit appear deployable/CI-green.
- Fake `pull_request` events (`opened`, `labeled`, `unlabeled`, `closed`) causing review stacks to be archived/unarchived or the merge queue to be manipulated.
- Fake `membership` events creating arbitrary `Team`/`User` records.

Forged CI/status state is a direct path toward an unauthorized deploy decision (a human or automation later deploys based on a falsely "green" commit), and forged pull-request/merge events can affect the merge queue for a repository the attacker does not control — matching the required "unauthorized deploy/merge" / "unauthenticated write of stack state" impact classes.

### Likelihood Explanation
Requires no credentials, no `ApiClient` token, and no GitHub repository access — only that the target Shipit instance hosts at least one organization without a `webhook_secret` (a state the shipped example config and docs treat as normal/default, e.g. single-org setups often leave it blank in development, and nothing enforces it be set in multi-org mode). Any internet-reachable Shipit instance in this configuration is exploitable by a fully unprivileged, unauthenticated actor who can just POST JSON to the public `/github/webhooks` endpoint.

### Recommendation
- Verify the webhook signature using the organization/App actually implicated by every field that will be trusted for writes (`repository.full_name`'s owner segment), not a separately-chosen `repository_owner`/`organization.login` field.
- Do not implicitly treat a blank `webhook_secret` as "signature verified"; require an explicit opt-in (and log/alarm) for orgs running without a secret, and never let such an org's "success" implicitly authorize writes to a different organization's data.
- Cross-check that `repository.owner.login` (used to select the verifying secret) equals the owner segment parsed out of `repository.full_name` before dispatching to handlers.

### Proof of Concept
1. Configure two organizations in `config/secrets.yml`: `org-without-secret` (webhook_secret left blank) and `victim-org` (webhook_secret set, real GitHub App installed with a real stack `victim-org/victim-repo`).
2. As an unauthenticated attacker, POST to `/github/webhooks` with header `X-Github-Event: status` and no valid `X-Hub-Signature` (or any garbage value), body:
```json
{
  "repository": { "owner": { "login": "org-without-secret" }, "full_name": "victim-org/victim-repo" },
  "sha": "<victim commit sha>",
  "state": "success",
  "context": "ci/required-check",
  ...
}
```
3. `verify_signature` selects `Shipit.github(organization: "org-without-secret")`; since its `webhook_secret` is blank, `verify_webhook_signature` returns `true` and the request proceeds.
4. `StatusHandler` (via `Handler#stacks`/`repository_name`) resolves `victim-org/victim-repo` from `repository.full_name` and records the forged status on the victim commit, with no interaction with `victim-org`'s real secret at any point.

### Citations

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
