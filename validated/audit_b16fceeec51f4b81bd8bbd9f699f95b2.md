### Title
Webhook signature is verified against the organization derived from `repository.owner.login`, but write actions are dispatched against a different, unverified field (`repository.full_name`) — allowing a webhook signed by one onboarded organization's secret to act on another organization's stacks - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to validate the HMAC signature against using `repository_owner`, computed from `params.dig('repository', 'owner', 'login')` (or `organization.login`). All downstream `Webhooks::Handlers` (e.g. `PushHandler`, `StatusHandler`) instead resolve the target `Repository`/`Stack` using a *different* JSON field, `payload.dig('repository', 'full_name')`, via `Handler#repository_name`/`#stacks`. No code cross-checks that `repository.owner.login` (the field the signature was verified against) matches the owner embedded in `repository.full_name` (the field actually used to select which repository/stack is mutated).

### Finding Description
`verify_signature` fetches `Shipit.github(organization: repository_owner)` and validates `X-Hub-Signature` against that organization's configured `webhook_secret`: [1](#0-0) [2](#0-1) 

Once the signature is accepted, the raw payload is dispatched unmodified to handlers: [3](#0-2) 

Every handler resolves its target repository/stacks from `payload.dig('repository', 'full_name')`, a field that was never part of the value used to pick the verification secret: [4](#0-3) 

`PushHandler` then triggers a real GitHub sync (`stack.sync_github`) for every non-archived stack of whatever repository `full_name` names, using an attacker-controlled `after` SHA from the same payload: [5](#0-4) 

`Repository.from_github_repo_name` simply splits `full_name` on `/` and looks the record up by `owner`/`name`, with no relation back to the `repository.owner.login`/`organization.login` value that gated signature verification: [6](#0-5) 

This is the exact analog class called out in the rules: **"an organization that authenticated versus the repository that is written."** GitHub's own webhook deliveries always keep `repository.owner.login` and `repository.full_name` consistent, but the engine never enforces this invariant itself — it trusts that whichever org's secret validated the HMAC is also the org whose repository is embedded in `full_name`. Any actor who legitimately administers the GitHub webhook settings of **one** organization already onboarded to this Shipit instance (i.e., who knows that org's own `webhook_secret`, which they configured themselves when connecting their org to Shipit — not a Shipit credential, and not access to any other org) can craft an arbitrary raw JSON body, sign it with their own org's secret, set `repository.owner.login`/`organization.login` to their own org (to pass `verify_signature`) while setting `repository.full_name` to `victim-org/victim-repo`. The forged `push` event is accepted and dispatched, causing `PushHandler` to call `stack.sync_github(expected_head_sha: <attacker-chosen sha>)` against a stack belonging to a completely unrelated, victim organization/repository that the attacker has no GitHub permissions on.

### Impact Explanation
This breaks a cross-tenant trust boundary: an org that is only entitled to emit verifiably-signed events for its own repositories can instead force sync/state changes on another organization's `Stack` records by forging the `repository.full_name` field, which is never covered by the signature-selection logic. Depending on which handler is targeted (`push`, `status`, `check_suite`, `membership`, `pull_request/*`), this enables cross-repository writes (unauthorized commit/stack syncing, forged commit statuses, forged team membership changes) driven entirely by a payload field that was excluded from the authentication binding — matching the report's "Critical: cross-repository writes" category.

### Likelihood Explanation
Requires the attacker to control (or have previously configured) the GitHub webhook delivery for at least one organization already onboarded to the target Shipit instance — a materially lower bar than requiring a Shipit account, `ApiClient` token, or GitHub App private key, since organization webhook secrets are commonly known to any admin of that org and are unrelated to permissions on any other org's repositories.

### Recommendation
In `WebhooksController#verify_signature` (or in `Handler#repository_name`), assert that the field used to select the verification secret (`repository.owner.login` / `organization.login`) is identical to the owner segment parsed out of `repository.full_name` before dispatching to handlers; reject the request (422) on mismatch.

### Proof of Concept
1. Attacker administers `org-attacker`, which is legitimately connected to the target Shipit instance with a known `webhook_secret` (`S_attacker`), and knows a valid stack `org-victim/victim-repo` exists on the same Shipit instance.
2. Attacker crafts a `push` event JSON body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "owner": { "login": "org-attacker" },
    "full_name": "org-victim/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC-SHA1(S_attacker, body)` and POSTs to `/webhooks` with `X-Github-Event: push`.
4. `verify_signature` computes `repository_owner = "org-attacker"`, fetches `Shipit.github(organization: "org-attacker")`, and validates the signature successfully against `S_attacker`.
5. `PushHandler.call(params)` runs, `Handler#repository_name` reads `full_name` = `"org-victim/victim-repo"`, resolves that `Repository`'s stacks, and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` for the `master` branch stack of `org-victim/victim-repo`, despite the attacker having no legitimate signing relationship with `org-victim`.

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
