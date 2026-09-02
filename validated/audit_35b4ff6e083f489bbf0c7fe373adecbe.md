### Title
Webhook signature verification keys off a different payload field than the one used to select the affected repository, allowing forged events to be accepted when any configured GitHub organization has no `webhook_secret` - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`Shipit::WebhooksController#verify_signature` selects which `GitHubApp` (and therefore which `webhook_secret`) to validate an inbound webhook against using `repository_owner`, derived from `params.dig('repository', 'owner', 'login')` or `params.dig('organization', 'login')`. The actual handler that decides which `Stack`/`Repository` the event acts on (`Shipit::Webhooks::Handlers::Handler#repository_name`) uses a *different* field of the same untrusted JSON body: `payload.dig('repository', 'full_name')`. `GitHubApp#verify_webhook_signature` returns `true` unconditionally when that organization's `webhook_secret` is blank/unset. This breaks the intended binding "organization authenticated == repository written."

### Finding Description [1](#0-0) 
`verify_signature` computes `repository_owner` from the request body itself (unauthenticated, attacker-controlled at this point), then does `Shipit.github(organization: repository_owner)` to fetch that organization's app config and verify against its secret: [2](#0-1) 

`GitHubApp#verify_webhook_signature` short-circuits to `true` when the organization's configured `webhook_secret` is blank: [3](#0-2) 

Meanwhile, once `create` dispatches to a handler, the handler resolves which `Repository`/`Stack` to mutate using a *different* field, `repository.full_name`, not the `repository.owner.login` used for verification: [4](#0-3) [5](#0-4) 

In a multi-organization Shipit deployment (the engine explicitly supports per-organization GitHub App configs, see `TOP_LEVEL_GH_KEYS` and `Shipit.github(organization:)` lookup by org), the binding the code implicitly assumes is:

`organization_used_to_select_webhook_secret == organization_that_owns_the_repository_being_acted_on`

If any one configured organization in the instance has no `webhook_secret` set (a supported, non-error configuration — `webhook_secret` is `.presence`-guarded and optional), an attacker can send a POST to `/webhooks` with `repository.owner.login` set to that unconfigured organization (satisfying `verify_signature` unconditionally) while setting `repository.full_name` to any other organization/repository tracked by Shipit. The handler will then act on the target stack using the forged payload contents, even though the signature verification never validated anything tied to that target organization.

### Impact Explanation
This crosses the "GitHub identity authenticated vs. resource written" trust boundary called out in scope: signature verification for org A is used to authorize writes against org B's stack. Depending on which handler processes the event this enables:
- `push` events forging `after`/`ref` to trigger `Stack#sync_github` against an arbitrary tracked repository/branch [5](#0-4) 
- `status` events forging commit build/CI state for arbitrary commits by `sha`, which can unlock deploy gating (`Commit#create_status_from_github!`) [6](#0-5) 
- `check_suite`, `pull_request`, and `membership` handlers are reached the same way via `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` in the controller [7](#0-6) 

Forged `status` events can flip CI/deployable status of a commit in a tracked repository, which the engine's deploy gating logic elsewhere treats as a prerequisite for allowing an "unauthorized ship" (deploy). This satisfies the required Critical/High impact bar of "an unauthorized deploy."

### Likelihood Explanation
Exploitability is entirely conditioned on the deployment's configuration: it requires (a) a multi-organization Shipit setup, and (b) at least one configured organization lacking a `webhook_secret`. The rules state analogs must not "depend on the host application not mounting the engine as documented" — configuring an org without a `webhook_secret` is a supported, documented code path (`.presence` guard, not an error), not a misconfiguration outside the engine's own logic. However, I could not fully verify from the indexed code whether the documented/standard setup instructions always mandate a `webhook_secret` for every org (docs/setup.md was only partially inspected), so likelihood is moderate and conditional rather than certain to apply to every deployment.

### Recommendation
Bind the field used to select the verifying `webhook_secret` to the same field used by handlers to resolve the target repository/stack (i.e., verify against `repository.full_name`'s owner consistently, or re-validate that `repository.full_name`'s owner matches the organization whose secret validated the signature before dispatching to any handler). Additionally, do not allow `verify_webhook_signature` to return `true` when no secret is configured for a production/multi-tenant deployment — require an explicit "unauthenticated org" opt-in rather than a silent bypass, and reject webhooks whose `repository.owner.login` does not match `repository.full_name`.

### Proof of Concept
Preconditions: Shipit instance configured with organizations `trusted-org` (no `webhook_secret` set) and `victim-org` (has stacks tracked, `webhook_secret` set).

1. Attacker POSTs to `/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/main",
  "after": "deadbeef",
  "repository": {
    "owner": { "login": "trusted-org" },
    "full_name": "victim-org/production-repo"
  }
}
```
2. `WebhooksController#verify_signature` computes `repository_owner = "trusted-org"`, calls `Shipit.github(organization: "trusted-org")`, whose `webhook_secret` is blank → `verify_webhook_signature` returns `true` unconditionally [8](#0-7) . No `X-Hub-Signature` needs to be valid/present in a meaningful way.
3. Request passes verification and reaches `create`, which dispatches to `Handlers::PushHandler` [9](#0-8) .
4. `PushHandler#process` resolves `stacks` via `Repository.from_github_repo_name(repository_name)` where `repository_name = payload.dig('repository', 'full_name')` = `"victim-org/production-repo"` [4](#0-3) , and calls `stack.sync_github(expected_head_sha: params.after)` on `victim-org`'s stacks — despite the request never being authenticated against `victim-org`'s secret.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/webhooks.rb (L6-9)
```ruby
      def default_handlers
        {
          'push' => [Handlers::PushHandler],
          'pull_request' => [
```
