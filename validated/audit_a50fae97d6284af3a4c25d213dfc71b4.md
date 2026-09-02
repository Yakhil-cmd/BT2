### Title
Webhook signature verification selects a GitHub organization independently from the repository the payload's handlers act on, allowing secret-less forgery of events for any stack - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` picks *which* organization's webhook secret to validate the HMAC signature against using `repository_owner`, a value taken from the JSON payload itself. The handler that subsequently executes the event (`Handler#stacks`) resolves the actual repository/stack to mutate using a *different* payload field, `repository.full_name`. These two fields are never cross-checked, and per-organization webhook secrets are optional, so an attacker can pick an onboarded organization that has no secret configured to satisfy `verify_signature`, while pointing `repository.full_name` at a completely different, victim organization/repository whose `Stack` is then acted upon.

### Finding Description
`verify_signature` derives the signing organization purely from the payload: [1](#0-0) [2](#0-1) 

The signature check itself is a no-op whenever the resolved organization has no `webhook_secret` configured: [3](#0-2) 

Shipit explicitly supports multiple GitHub organizations, each with its own independently configured `webhook_secret` (including `nil`), as documented/exercised in `config/secrets.development.example.yml` and `test/dummy/config/secrets_double_github_app.yml`: [4](#0-3) [5](#0-4) 

However, once `verify_signature` passes, every event handler resolves the concrete repository/stack to operate on from a *separate* payload field, `repository.full_name`, with no cross-check against `repository_owner`: [6](#0-5) 

`PushHandler`, for instance, uses that resolved stack set to trigger a GitHub sync using an attacker-supplied `after` SHA: [7](#0-6) 

This is the same class of bug as the report's "processing of initial balances": one part of the code establishes an authorization/trust decision from field A of the input (here, `repository.owner.login` used to choose the verifying secret), while a different part of the code performs the state-changing action based on field B of the same input (`repository.full_name`), without binding A and B together. The equality that should hold but does not:

`organization authenticated by verify_signature == organization/repository whose Stack is mutated by the Handler`

### Impact Explanation
An attacker who knows (or can determine) the name of any GitHub organization onboarded into a given Shipit deployment's multi-org config that has `webhook_secret` unset/blank can send an unauthenticated, unsigned raw HTTP POST to the public `/webhooks` (or mounted equivalent) endpoint with:
- `repository.owner.login` (or `organization.login`) = the no-secret org (satisfies `verify_signature` trivially, since `return true unless webhook_secret`)
- `repository.full_name` = `"victim-org/victim-repo"` (any other onboarded org/repo)

The request will be processed by the real event handlers against the victim stack. For the `push` event this forces `Stack#sync_github(expected_head_sha:)` to run for the victim's stacks with an attacker-chosen SHA, and other handlers (status, check_suite, membership, pull_request family) are reachable the same way, all without any credential, token, or webhook secret for the targeted organization. This is a cross-repository, cross-organization write triggered without authentication, matching the Critical "cross-repository writes"/unauthorized action bucket.

### Likelihood Explanation
Exploitation requires no secret, token, or privileged account — only knowledge of an organization name configured in the target Shipit instance without a `webhook_secret` (or, for single-secret deployments, if the operator ever leaves `webhook_secret` unset for testing/staging as shown to be a supported, documented configuration). No GitHub-side action is needed; the attacker interacts directly with Shipit's public webhook endpoint.

### Recommendation
Bind the organization used for signature verification to the same repository identity used by the handlers: derive both from the same field (e.g., always use `repository.full_name`'s owner segment), and reject the request if `repository.owner.login`/`organization.login` and the owner segment of `repository.full_name` disagree. Additionally, do not silently treat a missing `webhook_secret` as "signature verification passed" in production; require an explicit, documented opt-in (or reject) instead of `return true unless webhook_secret` in `GitHubApp#verify_webhook_signature`.

### Proof of Concept
1. Configure (or observe) a Shipit multi-org deployment where organization `orgA` has `webhook_secret: nil` and organization `orgB` (`victim-org`) has a real stack tracking `victim-org/victim-repo`.
2. POST to the Shipit webhook endpoint with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/master",
  "after": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
  "repository": {
    "owner": { "login": "orgA" },
    "full_name": "victim-org/victim-repo"
  }
}
```
No `X-Hub-Signature` header, or any arbitrary value, is required.
3. `verify_signature` resolves `repository_owner` = `orgA`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` unconditionally (`lib/shipit/github_app.rb#L76-L83`).
4. `PushHandler#process` resolves `stacks` via `Repository.from_github_repo_name("victim-org/victim-repo")` (`app/models/shipit/webhooks/handlers/handler.rb#L32-L38`) and calls `stack.sync_github(expected_head_sha: "deadbeef...")` on the victim's stack, entirely unauthenticated.

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

**File:** config/secrets.development.example.yml (L8-16)
```yaml
github:
  app_id:
  installation_id:
  webhook_secret: # nil
  private_key:
  oauth:
    id:
    secret:
    teams: # Optional
```

**File:** test/dummy/config/secrets_double_github_app.yml (L1-10)
```yaml
  github:
    OrgOne:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
      # Randomly generated
      private_key: |
        -----BEGIN RSA PRIVATE KEY-----
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L6-17)
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
```
