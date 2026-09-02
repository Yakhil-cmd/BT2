### Title
Webhook signature bypass when `webhook_secret` is unset for an org allows unauthenticated stack archive/deprovision - ([File: lib/shipit/github_app.rb](lib/shipit/github_app.rb))

### Summary
`GitHubApp#verify_webhook_signature` treats an absent or blank `webhook_secret` as automatic verification success, so `WebhooksController#verify_signature` never rejects the request for orgs configured without a secret. [1](#0-0)  Because the org used to select the `GitHubApp` config is taken directly from the unauthenticated request body (`params.dig('repository','owner','login')`), any internet client can POST an unsigned `pull_request` `closed` payload naming that org's real repository and trigger `Shipit::Webhooks::Handlers::PullRequest::ClosedHandler#process` → `ReviewStackAdapter#archive!`, which deprovisions and archives the live review stack. [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) 

### Finding Description
The claimed binding: `verified == (signature cryptographically matches HMAC(webhook_secret, raw_body))` for every org, for every request. What the code actually implements is `verified == true` whenever `@config[:webhook_secret]` is blank/absent for the org resolved from `repository_owner`, regardless of any signature:

```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
``` [1](#0-0) 

`WebhooksController#verify_signature` is a `before_action` that resolves the `GitHubApp` for `repository_owner` (parsed straight from `params.dig('repository','owner','login')`, attacker-controlled) and calls `verify_webhook_signature`; if it returns `true`, the filter chain is not halted and `#create` proceeds to dispatch the parsed payload to the matching handler. [6](#0-5) [2](#0-1) 

For a `pull_request` `closed` event, this reaches `ClosedHandler#process`, which (once `params.action == "closed"`) calls `review_stack.archive!` with no further authorization check. [7](#0-6)  `ReviewStackAdapter#archive!` looks up the stack by `environment` (derived from repo/PR number) and, if it exists and isn't already archived, calls `stack.remove_from_provisioning_queue`, `stack.deprovision`, and `stack.archive!(user)` using a `user` resolved from the attacker-supplied `sender.login`. [5](#0-4) [8](#0-7) 

No other guard intervenes: `drop_unhandled_event` only checks the event type is handled, not authenticity, and `check_if_ping` only special-cases `ping`. [9](#0-8)  The controller has no session/API-token requirement (`ActionController::Base`, no `require_permission!`/`force_github_authentication`), so the signature check is the *only* authentication mechanism for this endpoint, and it is bypassed by omission of `webhook_secret`.

The project's own setup documentation labels the webhook secret as **optional**: "Webhook secret (optional): Fill it with some randomly generated string..." and the shipped example configs (`config/secrets.development.example.yml`, `config/secrets.development.shopify.yml`) ship with `webhook_secret: # nil` for both single-org and multi-org setups. [10](#0-9) [11](#0-10)  This means the documented, supported configuration path for a newly onboarded org (or any org an operator has not yet supplied a secret for) leaves that org's `/webhooks` endpoint fully open to forged deliveries.

### Impact Explanation
Any unauthenticated client that knows (a) an org has no configured `webhook_secret` and (b) the `owner/repo` and PR number of a live review stack can force `Shipit::ReviewStack#deprovision` and `#archive!` to run against that stack with a single unsigned HTTP POST. This is a state-changing action on infrastructure (deprovisioning/archiving a real deploy environment) triggered by a party who never proved control of the GitHub org or repository — matching the "authentication bypass (forged webhook ... accepted)" Critical category. The attack is repeatable against every repository under the affected org and against any handler reachable via `/webhooks` (push, status, membership, other `pull_request` actions), not just `ClosedHandler`, since the bypass is at the controller's `verify_signature` layer, not the handler.

### Likelihood Explanation
The vulnerability requires exactly one precondition entirely outside the attacker's control: the target org's `Shipit.github_apps` entry has no (or blank) `webhook_secret`. This is a real, documented, supported state — the setup guide calls the secret "optional" and the shipped example secrets files leave it blank by default. No GitHub secret, session, or API token is needed by the attacker; a single crafted `POST /webhooks` request with `X-Github-Event: pull_request` and a JSON body naming the target repo/PR is sufficient, with no signature header required at all.

### Recommendation
Do not treat a missing `webhook_secret` as automatic verification success. `GitHubApp#verify_webhook_signature` should fail closed (return `false`/raise) when no secret is configured, or Shipit should refuse to boot/serve `/webhooks` for orgs lacking a `webhook_secret`. Update `docs/setup.md` and the example secrets files to make `webhook_secret` mandatory rather than "optional," and add a startup-time validation that every entry in `Shipit.github_apps` includes a non-blank `webhook_secret`.

### Proof of Concept
Add a minitest to `test/controllers/webhooks_controller_test.rb` (or a new handler-level test) asserting the equality that currently fails:

```ruby
test "unsigned pull_request closed event is rejected when org has no webhook_secret configured" do
  stack = shipit_stacks(:review_stack) # a live, non-archived ReviewStack
  Shipit.github_apps.stubs(:[]).returns({}) # simulate config hash without :webhook_secret
  # or: Shipit.stubs(:github).with(organization: 'shopify').returns(Shipit::GitHubApp.new('shopify', {}))

  request.headers['X-Github-Event'] = 'pull_request'
  body = JSON.parse(payload(:pull_request_closed))
  body['repository']['full_name'] = stack.github_repo_name
  # deliberately NOT setting X-Hub-Signature

  assert_no_changes -> { stack.reload.archived? }, from: false do
    post :create, body: body.to_json, as: :json
  end
  # Current code makes this assertion FAIL: stack.archived? becomes true
  # and Shipit::Stack#deprovision / #archive! get invoked with an attacker-chosen sender.login,
  # proving the request was accepted as authentic without any valid signature.
end
```

Both sides of the binding — "request is authenticated" vs. "request was accepted and mutated `stack`" — diverge under this precondition, confirming the bypass.

### Citations

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/controllers/shipit/webhooks_controller.rb (L19-22)
```ruby
    def drop_unhandled_event
      # Acknowledge, but do nothing
      head(204) unless Shipit::Webhooks.for_event(event).present?
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

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L41-63)
```ruby
          def process
            return unless respond_to_pull_request_closed?

            review_stack.archive!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end

          def review_stack
            @review_stack ||=
              Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks)
          end

          def respond_to_pull_request_closed?
            params.action == "closed"
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L23-35)
```ruby
          def archive!(*args, &block)
            if stack.blank?
              Rails.logger.info(
                "Processing #{action} event for #{repo_name} PR #{pr_number} but no Stack exists. Ignoring."
              )
              return true
            end
            return if stack.archived?

            stack.remove_from_provisioning_queue
            stack.deprovision
            stack.archive!(user, *args, &block)
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L52-54)
```ruby
          def user
            @user ||= Shipit::User.find_or_create_by_login!(params.sender["login"])
          end
```

**File:** docs/setup.md (L29-30)
```markdown
  - Webhook URL: It must be set to `<homepage>/webhooks`, e.g. `https://example.com/webhooks`.
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
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
