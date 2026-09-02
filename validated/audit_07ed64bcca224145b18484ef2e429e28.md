### Title
Webhook signature verification is keyed on `repository.owner.login`, but write actions are keyed on the unbound `repository.full_name` field, and signature checks silently no-op when an org has no `webhook_secret` configured - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects *which* GitHub App/secret to validate a webhook against using `repository.owner.login` (falling back to `organization.login`), [1](#0-0) [2](#0-1) . Every downstream handler, however, resolves the *repository actually acted upon* from a completely different, independently-controlled field in the same payload: `repository.full_name` [3](#0-2) . This mirrors the reported bug class ("many conversion/validation paths treat attacker-influenced fields as if they were mutually consistent without checking them"), except here the missing check is a binding between the field used to authenticate the sender and the field used to select the write target, not a `Result::unwrap()`.

### Finding Description
`GitHubApp#verify_webhook_signature` is defined as:
```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
``` [4](#0-3) 

When an organization is configured (per the documented multi-org schema in `config/secrets.*.yml` and `docs/setup.md`) without a `webhook_secret` — which the setup docs present as an optional field ("If you've set a webhook secret ... you should copy it here") [5](#0-4)  — `verify_webhook_signature` returns `true` unconditionally, regardless of the actual `X-Hub-Signature` header or body content.

Crucially, the *only* field used to pick which `GitHubApp`/secret applies is `repository.owner.login` / `organization.login`: 
```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [6](#0-5) 

But once `verify_signature` passes (trivially, for a secret-less org), the `create` action hands the entire unvalidated JSON body to the registered handlers [7](#0-6) , and every handler resolves the target repository from `repository.full_name` — a field that is never cross-checked against `repository.owner.login`:
```ruby
def repository_name
  payload.dig('repository', 'full_name')
end
``` [8](#0-7) 

This same pattern repeats in `PushHandler`, `OpenedHandler`, `ClosedHandler`, `ReopenedHandler`, `EditedHandler`, `LabelCapturingHandler`, etc., all of which call `Repository.from_github_repo_name(params.repository.full_name)` to find the stack to act on [9](#0-8) .

**Before/after the attack:**
- Before: `repository.owner.login = "orgA"` (configured with no `webhook_secret`) ⇒ verification is a no-op ⇒ trust binding "signature verified for orgA" is vacuous.
- After: the same request body sets `repository.full_name = "orgB/target-repo"`, and Shipit performs a real write (`GithubSyncJob`, review-stack archive/unarchive, `Status` creation, membership changes) against `orgB`'s stack, which the attacker never authenticated for and has no relationship to.

The equality that should hold — "the organization whose credential authorized this request" == "the organization/repository being written to" — is broken because the two are read from unrelated JSON fields with no cross-validation, and the authentication step can be a complete no-op for any org lacking a configured secret.

### Impact Explanation
This allows an unauthenticated attacker (no `webhook_secret`, no `ApiClient` token, no GitHub credentials) to inject arbitrary webhook events that trigger unauthorized writes against **any** stack/repository tracked by the Shipit instance — including `push` events that enqueue `GithubSyncJob` for a stack's `expected_head_sha`, `status`/`check_suite` events that alter commit statuses, and `pull_request` events that archive/unarchive/label review stacks — as long as at least one configured GitHub org in the deployment has no `webhook_secret` set. This satisfies the "unauthorized deploy/rollback/merge"-class impact criterion, since triggering `sync_github`/status changes directly influences whether a stack is judged deployable and can unblock or misdirect deploys.

### Likelihood Explanation
Likelihood is high wherever a multi-org Shipit deployment has even one organization configured without a `webhook_secret` (an explicitly documented, optional configuration) — the attacker needs no credentials at all, just the ability to POST JSON to the public `/github/webhooks` endpoint with a `X-Github-Event` header naming any handled event and an `owner.login`/`organization.login` matching the secret-less org.

### Recommendation
- Require `webhook_secret` to be present for every configured GitHub organization; fail closed (reject the webhook) rather than trusting the request when no secret is configured, instead of `return true unless webhook_secret` in `GitHubApp#verify_webhook_signature`.
- Bind the field used to select the verifying organization to the field used to resolve/act on the repository: after signature verification, re-derive/validate that `repository.full_name`'s owner matches the `repository_owner` used to select the verifying `GitHubApp`, and reject the request otherwise.

### Proof of Concept
1. Deploy Shipit with two organizations configured, e.g. `orgA` (no `webhook_secret` set, per the documented optional field) and `orgB` (has a tracked stack, e.g. `orgB/target-repo`).
2. POST to `/github/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-controlled sha>",
  "repository": {
    "full_name": "orgB/target-repo",
    "owner": { "login": "orgA" }
  }
}
```
3. `verify_signature` computes `Shipit.github(organization: "orgA")` and calls `verify_webhook_signature`, which returns `true` immediately since `orgA` has no `webhook_secret` — no valid `X-Hub-Signature` is required.
4. `PushHandler#process` resolves `stacks` via `Repository.from_github_repo_name("orgB/target-repo")` and enqueues `GithubSyncJob` for `orgB`'s stack [10](#0-9) , despite the request never having been authenticated for `orgB`.

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

**File:** docs/setup.md (L117-119)
```markdown
**`github.bot_login`** The login of the App [bot] user. Every GitHub App have an associated `[bot]` user which acts as the author of the App actions through the API, for example when an App merges a Pull Request. It should be the App "slug" with the suffix `[bot]`. For example if your app settings URL is `https://github.com/organizations/ACME/settings/apps/acme-shipit/installations`, the bot user should be `acme-shipit[bot]`. If you are unsure, you can leave it empty.

**`github.webhook_secret`** If you've set a webhook secret during the App creating, you should copy it here.
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
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
