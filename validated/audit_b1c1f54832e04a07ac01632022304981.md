Confirmed: `Repository.from_github_repo_name` at [1](#0-0)  looks up a `Repository` purely by the `owner/name` parsed out of the attacker-supplied payload `repository.full_name` field, with no cross-check against which GitHub organization's secret actually validated the request.

### Title
Webhook signature verification is keyed to an attacker-controlled `repository.owner.login` field, decoupling the authenticated organization from the repository/stack actually mutated - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects *which* GitHub App config (and therefore which `webhook_secret`) to verify the HMAC signature against using `repository_owner`, a value read directly out of the untrusted, not-yet-verified JSON body. `GitHubApp#verify_webhook_signature` then contains `return true unless webhook_secret` - i.e. if the organization selected by that untrusted field has no `webhook_secret` configured, verification is bypassed entirely and the request is treated as authentic. Handlers such as `PushHandler` and the `PullRequest` handlers then act on a *different* payload field, `repository.full_name`, to look up the target `Repository`/`Stack` via `Repository.from_github_repo_name`, which matches globally by `owner/name` with no re-validation that this repository belongs to the organization that was supposedly authenticated.

### Finding Description
The trust chain is:
1. `repository_owner` (from `params.dig('repository','owner','login')` or `params.dig('organization','login')`) picks the `GitHubApp` instance/secret used to check `X-Hub-Signature`: [2](#0-1)  and [3](#0-2) .
2. `verify_webhook_signature` short-circuits to `true` whenever that organization's `webhook_secret` is blank: [4](#0-3) . `webhook_secret` is an optional/commented-out field in every documented config template (`config/secrets.development.example.yml`, `docs/setup.md`, `template.rb`), so a Shipit install that manages several GitHub organizations (multi-org config block) can easily have one organization configured without a secret while others do have one.
3. Once `head(422)` is *not* set (verification "succeeds"), `create` dispatches the same raw payload to handlers: [5](#0-4) .
4. Handlers resolve the target purely from `repository.full_name` in the body, independent of `repository_owner`: `Shipit::Webhooks::Handlers::Handler#stacks` at [6](#0-5) , used by `PushHandler#process` at [7](#0-6) , and `Repository.from_github_repo_name` at [1](#0-0)  which does a plain `find_by(owner:, name:)` with no relation back to the organization/app that authenticated the request.

This breaks the intended binding `organization that authenticated == repository that is written`. An attacker who knows (or can guess) that one configured GitHub organization in a multi-org Shipit deployment has no `webhook_secret` set can forge an unsigned/arbitrarily-signed webhook whose `repository.owner.login` is that unsecured organization, while setting `repository.full_name` to `some-other-org/some-other-repo` belonging to a *different*, properly secured organization. Because signature verification never re-checks that `repository.full_name`'s owner matches the organization whose secret validated the request, the forged event is processed as if it came from GitHub for the other organization's repository, e.g. triggering `PushHandler#process` → `stack.sync_github(expected_head_sha:)` for a repository/stack the attacker does not control at GitHub.

### Impact Explanation
This crosses the "GitHub identity authenticated vs. repository/stack acted upon" trust boundary. Depending on which webhook events are wired to which handlers, an unauthenticated party can force sync/merge/deploy-adjacent state changes (`GithubSyncJob`, review-stack archive/unarchive/provisioning, PR record updates, commit statuses) against a stack belonging to an organization that never sent the request, which is a form of cross-repository/cross-organization write not authorized by that organization's own webhook secret. This is a High-severity authentication-boundary escalation analogous to the report's "gas limit not covering the actually-executed action" bug class: the field used for authorization (`repository_owner` → secret selection) is disjoint from the field used to select the object mutated (`repository.full_name`).

### Likelihood Explanation
Requires the deploying operator to run the documented multi-org `github:` config with at least one organization lacking `webhook_secret` (a state the shipped templates and docs explicitly present as a valid/optional configuration, not a hardening deviation), and requires the attacker to know or guess a valid `owner/name` pair for a target repository already tracked as a Shipit stack. No credentials, sessions, or tokens are required from the attacker side.

### Recommendation
After determining `repository_owner` for signature-secret selection, re-verify (post-signature-check) that every repository-identifying field acted upon by handlers (`repository.full_name`, `organization.login`) is consistent with the organization/app that actually validated the signature, and reject payloads where they diverge. Alternatively, disallow `webhook_secret` from ever being blank for a configured organization when Shipit is deployed in the multi-org configuration mode, so `verify_webhook_signature`'s trust-everyone fallback path can’t be reached for a configured org sharing infrastructure with a secured org.

### Proof of Concept
1. Configure Shipit with two GitHub orgs, e.g. `orgA` (no `webhook_secret`) and `orgB` (has `webhook_secret: S`), both with tracked stacks (`app/models/shipit/hook.rb`/config as in `config/secrets.development.shopify.yml`).
2. Send `POST /webhooks` with header `X-Github-Event: push` and no valid `X-Hub-Signature`, body:
```json
{ "ref": "refs/heads/main", "after": "<attacker-chosen sha>",
  "repository": { "owner": { "login": "orgA" }, "full_name": "orgB/target-repo" } }
```
3. `verify_signature` resolves `repository_owner` = `orgA`, looks up `Shipit.github(organization: "orgA")`, whose `webhook_secret` is `nil`, so `verify_webhook_signature` returns `true` unconditionally — the request passes verification without any valid signature.
4. `PushHandler#process` resolves stacks via `repository.full_name` = `orgB/target-repo`, unrelated to `orgA`, and calls `stack.sync_github(expected_head_sha: "<attacker-chosen sha>")`, causing Shipit to act on `orgB`'s stack based on a payload that `orgB`'s webhook secret never authenticated.

### Citations

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
