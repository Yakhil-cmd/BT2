### Title
Signature verification org (`repository.owner.login`) can diverge from mutated stack's org (`repository.full_name`), allowing unsigned webhook to enqueue `GithubSyncJob` for another organization's repository - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` derives the `GitHubApp` used for HMAC verification from `repository.owner.login`, while `Handler#stacks` (used by `PushHandler#process`) resolves the target `Repository`/`Stack` from `repository.full_name`. Because nothing enforces that these two fields name the same organization, an attacker can set `owner.login` to an org with no `webhook_secret` configured (making `verify_webhook_signature` return `true` unconditionally via its `return true unless webhook_secret` early-exit) while setting `full_name` to a different, secret-protected org's repository, causing an unsigned request to enqueue `GithubSyncJob` for that org's stack.

### Finding Description
The broken binding: the org whose `webhook_secret` verified the request bytes must equal the org owning the repository the handler mutates. In code: [1](#0-0) 

`repository_owner` is read from `params.dig('repository', 'owner', 'login')`: [2](#0-1) 

`Shipit.github(organization: repository_owner)` returns a `GitHubApp` for whatever org name is in `owner.login`, with no validation against `full_name`. If that org's config has no `webhook_secret` set, `verify_webhook_signature` short-circuits to `true` regardless of the signature header or body: [3](#0-2) 

After the (bypassed) signature check passes, `#create` re-parses the same raw body and dispatches to handlers: [4](#0-3) 

`PushHandler#process` calls `stacks`, which is defined in the base `Handler` class and resolves the repository from `payload.dig('repository', 'full_name')` — a completely different field than the one used for signature verification: [5](#0-4) [6](#0-5) 

Exploit flow: attacker POSTs `/webhooks` with header `X-Github-Event: push`, no `X-Hub-Signature` header (or any garbage value), and a JSON body where `repository.owner.login = "OrgA"` (an org configured in `Shipit.github` config without a `webhook_secret`) but `repository.full_name = "OrgB/some-repo"` (a real, tracked repository belonging to org B, which does have a `webhook_secret`). `verify_signature` looks up `Shipit.github(organization: 'OrgA')`, calls `verify_webhook_signature(nil_or_garbage, raw_post)`, which returns `true` immediately because `OrgA`'s `webhook_secret` is blank — no HMAC comparison ever happens. The request proceeds to `#create`, `PushHandler` resolves `Repository.from_github_repo_name('OrgB/some-repo')` from `full_name` and enqueues `GithubSyncJob` for OrgB's stack with the attacker-controlled `after` SHA.

Existing guards do not prevent this: `drop_unhandled_event` only checks the event type; `ExplicitParameters` (`params do requires :ref; requires :after end`) only validates presence of `ref`/`after`, not organizational consistency; there is no code anywhere cross-checking `owner.login` against `full_name`'s owner segment.

### Impact Explanation
A single unauthenticated HTTP POST causes `GithubSyncJob` to be enqueued against an arbitrary tracked stack belonging to a different, security-conscious organization, without any valid signature ever being checked against that organization's secret. This is a cross-repository/cross-tenant write triggered with zero valid HMAC — the request is fully attacker-controlled and repeatable against any repository/stack pair as long as one configured org lacks a `webhook_secret`. This matches the "Critical" category: a payload for one repository mutating another's stack, and effectively an authentication bypass since a forged/unsigned webhook is accepted as authoritative for a different org's data.

### Likelihood Explanation
Preconditions: at least one org configured in `Shipit.github`'s config must have no `webhook_secret` set (a plausible, common misconfiguration — e.g., a low-security or test organization added to the multi-org config) and at least one other tracked repository/stack must exist under a different org. Given these, the attacker's cost is a single unauthenticated HTTP request with no secrets, tokens, or GitHub access required, fully satisfying the "unprivileged attacker" constraints (no session, no `webhook_secret`, no API token needed). It is deterministically repeatable against any stack.

### Recommendation
Bind signature verification to the same organization that owns the resource being mutated: derive `repository_owner` for verification from the same `full_name` field used by handlers (e.g., parse the owner segment out of `repository.full_name` rather than trusting `owner.login`/`organization.login` independently), and/or reject requests where `owner.login` does not match the owner segment of `full_name`. Additionally, treat a missing `webhook_secret` as a configuration error rather than an implicit signature-bypass, or require operators to explicitly opt out per-organization instead of defaulting to `true`.

### Proof of Concept
```ruby
test "mismatched owner/full_name orgs bypass signature verification and sync another org's stack" do
  # OrgA has no webhook_secret configured (return true unless webhook_secret)
  Shipit.stubs(:github).with(organization: 'OrgA').returns(
    Shipit::GitHubApp.new('OrgA', {}) # no webhook_secret key
  )

  org_b_stack = shipit_stacks(:shipit) # belongs to "shopify"/OrgB, tracked in fixtures

  request.headers['X-Github-Event'] = 'push'
  # No X-Hub-Signature header set at all

  payload = JSON.parse(Shipit::WebhooksControllerTest.payload(:push_master))
  payload['repository']['owner']['login'] = 'OrgA'          # verified org
  payload['repository']['full_name'] = 'shopify/shipit-engine' # mutated org's repo (matches org_b_stack.repository)
  expected_head_sha = payload['after']

  assert_enqueued_with(job: GithubSyncJob, args: [stack_id: org_b_stack.id, expected_head_sha:]) do
    post :create, body: payload.to_json, as: :json
  end

  assert_response :ok
end
```
Both sides of the equality diverge: `Shipit.github(organization: 'OrgA')` (verified) ≠ `Repository.from_github_repo_name('shopify/shipit-engine').stacks` (mutated, owned by `OrgB`/`shopify`), proving the vulnerability.

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
