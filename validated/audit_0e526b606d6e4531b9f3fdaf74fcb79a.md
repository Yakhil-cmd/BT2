### Title
Webhook signature verification is bypassed for any org configured with `webhook_secret: nil` - (File: lib/shipit/github_app.rb)

### Summary
`GitHubApp#verify_webhook_signature` returns `true` immediately if no `webhook_secret` is configured for the organization, before ever inspecting the `X-Hub-Signature` header. Because `webhook_secret: nil` is the documented default/example configuration, an attacker can POST arbitrary, unsigned webhook payloads to `/webhooks` for that org's repositories and have them processed as authentic.

### Finding Description
The broken binding is: `verified == (signature was produced using the org's actual `webhook_secret`)`. In practice, `verify_webhook_signature` implements `verified == (webhook_secret.present?)`, not `verified == (valid HMAC over request.raw_post)`.

Code path: `WebhooksController#verify_signature` [1](#0-0)  resolves the GitHub app for the org via `Shipit.github(organization: repository_owner)`, where `repository_owner` is taken unauthenticated straight from the JSON body (`params.dig('repository','owner','login')`) [2](#0-1) . It then calls `github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)` and only calls `head(422)` if that returns `false`.

Inside `verify_webhook_signature`: `return true unless webhook_secret` [3](#0-2) . `@webhook_secret` is set from config in `initialize` via `@webhook_secret = @config[:webhook_secret].presence` [4](#0-3) . The shipped example configuration explicitly documents `webhook_secret` as commentable/nil: `webhook_secret: # nil` [5](#0-4) . When it's nil/blank, the method short-circuits to `true` without ever parsing or comparing the `X-Hub-Signature` header — so an omitted header, garbage header, or forged header are all treated identically to a genuine GitHub signature.

Once `verified` is `true`, `create` runs `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [6](#0-5) , dispatching to e.g. `AssignedHandler#process`, which loads the matching `PullRequest` scoped by `repository.full_name` from the payload and calls `pull_request.update(github_pull_request: params.pull_request)` [7](#0-6) . No other guard re-derives authentication: `drop_unhandled_event` only checks the event type is handled, and `check_if_ping` only special-cases `ping` — neither re-validates the sender. `GithubOrganizationUnknown` is only raised when the org name itself isn't configured, not when its secret is blank.

### Impact Explanation
For any organization whose Shipit config has `webhook_secret` unset (a state the shipped example config actively documents), an unauthenticated internet client can send arbitrary forged webhook events (`pull_request`, `push`, `status`, etc., any event with a registered handler) for that org's repositories, causing Shipit to write PullRequest/Commit/Stack state as if GitHub genuinely emitted the event. This is a full authentication bypass of the webhook boundary and is repeatable per-request and across every repository under that org. Depending on which handler is targeted, this can drive stack behavior (merge status changes, commit status updates, PR state) without any legitimate GitHub signature — matching the Critical "authentication bypass (forged webhook... accepted)" category.

### Likelihood Explanation
Precondition: the targeted org's entry in `secrets.yml` must have `webhook_secret` nil/blank — which is exactly the state shown in the shipped example config and plausible for real deployments that haven't set a secret (e.g., during initial setup, or orgs added without updating secrets). Attacker cost is a single unauthenticated HTTP POST with a JSON body and an `X-Github-Event` header; no secrets, sessions, or tokens are required. This is trivially repeatable against any repository under the misconfigured org.

### Recommendation
Do not treat a missing `webhook_secret` as "always verified." Either require `webhook_secret` to be present at boot/config-load time and fail closed, or make `verify_webhook_signature` return `false` when no secret is configured for a webhook-accepting installation (reject unsigned requests by default rather than accepting them).

### Proof of Concept
Minitest (`ActionDispatch::IntegrationTest`) plan:
1. Configure/stub the test org's `GitHubApp` so `webhook_secret` resolves to `''`/`nil` (matching `config/secrets.development.example.yml` shape), asserting `github_app.send(:webhook_secret)` is blank — this is the "before" state of the equality.
2. Create a `Stack`/`Repository`/`PullRequest` fixture whose repository full_name matches a payload's `repository.full_name`.
3. POST to `/webhooks` with `X-Github-Event: pull_request`, no `X-Hub-Signature` header, and a JSON body with `action: 'assigned'` matching `AssignedHandler`'s required params schema.
4. Assert response status is `200` (not `422`), proving `verify_signature` did not reject the unsigned request.
5. Assert the fixture `PullRequest` record was updated (e.g., its `github_pull_request` payload/state changed) proving `AssignedHandler#process` → `PullRequest#update` executed — demonstrating the "after" state: an unauthenticated write occurred despite no valid signature ever being checked, confirming `verified == webhook_secret.present?` rather than `verified == valid_signature?`.

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

**File:** lib/shipit/github_app.rb (L44-51)
```ruby
    def initialize(organization, config)
      super()
      @mutex = Mutex.new
      @organization = organization
      @config = (config || {}).with_indifferent_access
      @domain = @config[:domain] || DOMAIN
      @webhook_secret = @config[:webhook_secret].presence
      @bot_login = @config[:bot_login]
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

**File:** app/models/shipit/webhooks/handlers/pull_request/assigned_handler.rb (L41-69)
```ruby
          def process
            return unless respond_to_assignee_change?

            pull_request.update(github_pull_request: params.pull_request) if pull_request.present?
          end

          private

          def respond_to_assignee_change?
            %w[assigned unassigned].include?(params.action)
          end

          def pull_request
            @pull_request ||= Shipit::PullRequest
                              .joins(:stack, stack: :repository)
                              .find_by(
                                number: params.number,
                                stacks: {
                                  repositories:
                                    {
                                      id: repository.id
                                    }
                                }
                              )
          end

          def repository
            Shipit::Repository.from_github_repo_name(params.repository.full_name) || Shipit::NullRepository.new
          end
```
