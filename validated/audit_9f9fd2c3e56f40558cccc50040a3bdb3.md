### Title
Webhook organization/repository binding bypass allows unauthorized cross-repository writes via mismatched `repository.owner.login` and `repository.full_name` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/webhook secret to use for HMAC verification based on `repository_owner`, a value read directly from the still-unverified JSON request body. The handler that actually executes the webhook event (e.g. `PushHandler`) looks up the target repository/stack using a *different* field from the same unverified body: `repository.full_name`. Because these two fields are never checked for consistency, and because `GitHubApp#verify_webhook_signature` trivially returns `true` for any organization that has no `webhook_secret` configured, an attacker can pick an arbitrary weak/unconfigured organization to satisfy signature verification while making the payload act on a completely different, unrelated (properly secured) repository.

### Finding Description
This is the same rounding/binding-mismatch bug class as the Sherlock M-2 report: a value used for authorization/accounting (`_amount`) diverges from the value actually charged (`shares`) because two different computations of "the same" quantity aren't kept in sync. Here, two different fields of the same payload are treated as if they describe "the organization" but are never bound to each other:

- Signature verification org: [1](#0-0) 
- The org used is extracted from the raw JSON body via Rails' automatic JSON parameter parsing (i.e. before/independent of signature verification): [2](#0-1) 
- `GitHubApp#verify_webhook_signature` unconditionally passes when the selected organization has no `webhook_secret` configured: [3](#0-2) 
- `Shipit.github(organization:)` supports per-organization app configs, confirming multi-organization deployments are a supported, documented configuration (each org can have its own, possibly-empty, `webhook_secret`): [4](#0-3) , [5](#0-4) 
- After signature verification "passes," the event is dispatched to handlers using `params` parsed straight from `request.raw_post`: [6](#0-5) 
- The handler resolves the target stack using an entirely different field of the same payload, `repository.full_name`, with no relation enforced to the `repository.owner.login`/`organization.login` used for signature selection: [7](#0-6) 
- Example concrete handler that acts on the mismatched repository, triggering a GitHub sync of a stack based on attacker-supplied `ref`/`after` (commit SHA): [8](#0-7) 

The broken equality binding is: `organization used to select/verify the webhook secret` (`repository.owner.login` / `organization.login`) `== organization that owns the repository the event actually writes to` (`repository.full_name`'s owner). These are asserted to be equal by design (a webhook for repo X should be signed by X's org secret), but the code never checks it — it merely uses the former to pick a secret and the latter to pick a target.

### Impact Explanation
An unauthenticated network attacker who knows (a) that the Shipit instance is configured for multiple GitHub organizations and (b) that at least one configured organization has no `webhook_secret` (or one they know), can forge a webhook event for a repository belonging to a *different, fully-secured* organization. This can:
- Trigger unauthorized `GithubSyncJob`/`sync_github` calls that advance a stack's known SHA (`push` event, `PushHandler`), influencing what commits are eligible for deploy.
- Spoof commit statuses/check-runs (via `status`/`check_suite` handlers, which similarly resolve target repos via `repository.full_name`), potentially satisfying CI checks used to gate the merge queue or continuous deployment, leading to an unauthorized deploy or merge — squarely within the Critical impact bucket ("cross-repository writes, or an unauthorized deploy, rollback or merge").

### Likelihood Explanation
Requires only an HTTP POST to the public, unauthenticated `/webhooks` endpoint (`skip_before_action :verify_authenticity_token`) — no session, `ApiClient` token, or repository write access needed. The only precondition is a realistic, documented deployment shape: a Shipit instance serving more than one GitHub organization, at least one of which is configured without a `webhook_secret` (a state explicitly supported by `test/dummy/config/secrets_double_github_app.yml` and the `github` per-org config schema). This is not a host-misconfiguration outside the engine's control — the vulnerable binding logic lives entirely in `WebhooksController` and `Webhooks::Handlers::Handler`.

### Recommendation
After verifying the webhook signature, re-derive `repository_owner` from the same field the handlers use (`repository.full_name`'s owner segment) and reject the request if it does not match the organization whose secret was used to verify the signature. Alternatively, always verify against the specific organization owning `repository.full_name`, not a field that can independently diverge.

### Proof of Concept
Given a `secrets.yml` with two configured GitHub orgs, where `orgB` has no `webhook_secret`:
```
POST /webhooks HTTP/1.1
Content-Type: application/json
X-Github-Event: push

{
  "repository": {
    "full_name": "orgA/secured-repo",
    "owner": { "login": "orgB" }
  },
  "ref": "refs/heads/main",
  "after": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
}
```
- `verify_signature` calls `Shipit.github(organization: "orgB")`; since `orgB.webhook_secret` is blank, `verify_webhook_signature` returns `true` regardless of the (even absent) `X-Hub-Signature` header.
- `PushHandler` then resolves the target via `payload.dig('repository','full_name')` = `"orgA/secured-repo"`, invoking `stack.sync_github(expected_head_sha: "deadbeef...")` on `orgA`'s real, secured stacks — despite the request never being validated by `orgA`'s webhook secret.

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

**File:** lib/shipit.rb (L170-200)
```ruby
  def github(organization: github_default_organization)
    # Backward compatibility
    # nil signifies the single github app config schema is being used
    if github_default_organization.nil?
      config = secrets.github
    else
      config = github_app_config(organization)
      raise GithubOrganizationUnknown, organization if config.nil?
    end
    @github ||= {}
    @github[organization] ||= GitHubApp.new(organization, config)
  end

  def github_default_organization
    return nil unless secrets&.github

    org = secrets.github.keys.first
    TOP_LEVEL_GH_KEYS.include?(org) ? nil : org
  end

  def github_organizations
    return [nil] unless github_default_organization

    secrets.github.keys
  end

  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L6-24)
```ruby
      class PushHandler < Handler
        params do
          requires :ref
          requires :after
        end

        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end

        private

        def branch
          params.ref.gsub('refs/heads/', '')
        end
      end
```
