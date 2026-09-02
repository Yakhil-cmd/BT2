### Title
Webhook signature is verified against `repository.owner.login`'s secret while the push handler acts on `repository.full_name`, allowing cross-organization stack mutation - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`Shipit::WebhooksController#verify_signature` selects the HMAC secret to validate a webhook using `repository_owner` (`params.dig('repository','owner','login')`), but `Shipit::Webhooks::Handlers::Handler#stacks` resolves the target repository/stack using a different field, `payload.dig('repository','full_name')`. Because both fields are attacker-controlled parts of the same unauthenticated JSON body, an attacker who owns any GitHub App integration configured in `Shipit.github_apps` can sign a payload with their own secret while pointing `full_name` at a victim's repository, causing `PushHandler` to call `stack.sync_github` on a stack they do not control.

### Finding Description
The broken binding, stated as an equality that should hold but doesn't:
`organization_whose_secret_verified_signature (params.dig('repository','owner','login'))` == `organization_owning_mutated_stack (Repository.from_github_repo_name(payload.dig('repository','full_name')).owner)`

Trace:
- `before_action :check_if_ping, :drop_unhandled_event, :verify_signature` runs before `create`. [1](#0-0) 
- `verify_signature` computes `github_app = Shipit.github(organization: repository_owner)` and verifies the `X-Hub-Signature` HMAC using that org's `webhook_secret` via `GitHubApp#verify_webhook_signature`. [2](#0-1) 
- `repository_owner` is read straight from the untrusted body: `params.dig('repository', 'owner', 'login')`. [3](#0-2) 
- `verify_webhook_signature` only checks that the signature matches `HMAC(webhook_secret_for(repository_owner), raw_body)` — it never checks that `repository_owner` corresponds to the repository actually mutated by the handler. [4](#0-3) 
- On success, `create` re-parses `request.raw_post` and dispatches to `Shipit::Webhooks.for_event(event)` handlers, passing the same JSON. [5](#0-4) 
- `Handler#stacks` (base class used by `PushHandler`) resolves the repository using an entirely different field: `payload.dig('repository', 'full_name')`, then `Repository.from_github_repo_name(...)`. [6](#0-5) 
- `PushHandler#process` then finds non-archived stacks on the resolved repository matching the pushed branch and calls `stack.sync_github(expected_head_sha: params.after)`, where `params.after` is also attacker-controlled. [7](#0-6) 

Because `repository.owner.login` and `repository.full_name` are two independent fields in the same attacker-supplied JSON body, and only the first is used for authentication while the second is used for authorization/targeting, an attacker who legitimately owns an org configured in `Shipit.github_apps` (with their own known `webhook_secret`) can craft a body where:
- `repository.owner.login = "org-attacker"` → makes `verify_signature` pick org-attacker's secret, which the attacker knows and can correctly HMAC-sign.
- `repository.full_name = "org-victim/stack-repo"` → makes `PushHandler` resolve and mutate the victim's `Stack` via `Repository.from_github_repo_name`.

No component re-checks that the two fields agree. `ExplicitParameters` schema in `PushHandler` only requires `:ref` and `:after`, it does not validate repository ownership. `Repository::from_github_repo_name` performs a simple lookup with no ownership cross-check against the verifying app. `drop_unhandled_event` only checks the event type. There is no `force_github_authentication`, session, or API-client check on this unauthenticated webhook endpoint — that's expected, but the signature check is the *only* authentication mechanism, and it authenticates the wrong field relative to what's later trusted.

### Impact Explanation
An attacker who controls a GitHub App/org entry in `Shipit.github_apps` (i.e., any tenant org onboarded to the multi-tenant Shipit instance) can forge push webhooks that pass signature verification using their own secret, yet cause `Stack#sync_github(expected_head_sha: ...)` to run against another tenant's stack of their choosing, with an attacker-chosen `after` SHA. This is a cross-repository/cross-tenant write triggered by a payload that never had a valid signature for the victim's organization, matching the "payload for one repository mutating another's stack" Critical impact category. The attack is repeatable against any stack whose repository/branch is guessable (`Repository.from_github_repo_name` + branch), and is not limited to a single victim — any org present in `Shipit.github_apps` is a viable target.

### Likelihood Explanation
Preconditions: multi-tenant `Shipit.github_apps` configuration with at least two organizations, each with its own `webhook_secret`; the attacker must control (or be onboarded as) one of those organizations, which is inherent to how Shipit installations serve multiple orgs/teams. The attacker's cost is a single unauthenticated HTTP POST to `/webhooks` with a hand-crafted JSON body and a correctly computed HMAC using their own known secret — no privileged credentials, sessions, or victim secrets are required. This is straightforward and fully repeatable.

### Recommendation
In `Shipit::WebhooksController#verify_signature`/`#create` (or in `Handler`), ensure the organization/repository used to select the verifying secret is the same one the handler acts upon: after verifying the signature, re-derive `repository_owner` from `payload.dig('repository', 'full_name')` (splitting on `/`) rather than `repository.owner.login`, or explicitly assert `payload.dig('repository','owner','login') == payload.dig('repository','full_name').split('/').first` before dispatching to handlers, rejecting mismatches with a 422.

### Proof of Concept
Minitest plan (`test/controllers/shipit/webhooks_controller_test.rb`-style, no live GitHub, using stubbed `Shipit.github_apps`):
1. Configure `Shipit.github_apps` with two orgs: `org-attacker` (secret `secretA`) and `org-victim` (secret `secretB`).
2. Create `repository = Repository.create!(owner: 'org-victim', name: 'stack-repo')` and `stack = Stack.create!(repository:, branch: 'master')`.
3. Build JSON body: `{"ref" => "refs/heads/master", "after" => "deadbeef", "repository" => {"owner" => {"login" => "org-attacker"}, "full_name" => "org-victim/stack-repo"}}`.
4. Compute `signature = "sha1=" + OpenSSL::HMAC.hexdigest('sha1', 'secretA', body)`.
5. `Stack.any_instance.expects(:sync_github).with(expected_head_sha: 'deadbeef')` (or assert it's called on `stack` specifically).
6. `post shipit.webhooks_path, params: body, headers: { 'X-Github-Event' => 'push', 'X-Hub-Signature' => signature, 'CONTENT_TYPE' => 'application/json' }`.
7. Assert response is `:ok` (verify_signature passed using org-attacker's secret) AND assert `sync_github` was invoked on the victim's `stack` — demonstrating that `repository_owner` (`org-attacker`, used for auth) != the organization owning the mutated repository (`org-victim`, derived from `full_name`), yet the mutation proceeded.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L6-6)
```ruby
    before_action :check_if_ping, :drop_unhandled_event, :verify_signature
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
