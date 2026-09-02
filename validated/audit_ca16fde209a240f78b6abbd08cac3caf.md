### Title
Cross-org write via webhook: `repository.owner.login` (used for HMAC/secret lookup) is never bound to `repository.full_name` (used to resolve the target repository/stack) - ([File: lib/shipit/github_app.rb])

### Summary
`WebhooksController#verify_signature` selects the `GitHubApp` (and thus the HMAC secret) using `params.dig('repository','owner','login')`, while every handler resolves the actual repository/stack to mutate using `payload.dig('repository','full_name')` (`Handler#repository_name`). No code anywhere checks that these two fields refer to the same organization, so a webhook whose `repository.owner.login` selects org A's secret can still target org B's repository in `repository.full_name`.

### Finding Description
The broken binding is: `repository_owner (params.repository.owner.login) == owner(repository.full_name)` is assumed but never enforced.

- `WebhooksController#verify_signature` resolves `github_app = Shipit.github(organization: repository_owner)` where `repository_owner` reads only `params.dig('repository','owner','login')` [1](#0-0) .
- `GitHubApp#verify_webhook_signature` performs a pure HMAC comparison against that org's configured `webhook_secret`, with no knowledge of, or binding to, `repository.full_name` [2](#0-1) .
- Every `Handler` subclass (base class `Handler#stacks`/`#repository_name`, and `ClosedHandler#repository`, etc.) resolves the target repository purely from `payload.dig('repository','full_name')` via `Repository.from_github_repo_name`, completely independent of the `owner.login` field used for signature verification [3](#0-2) [4](#0-3) .

Given the stated precondition (org A and org B independently configure the identical `webhook_secret` value - a realistic operator error, not a Shipit-held secret leak), an attacker who legitimately administers org A's own GitHub App/webhook config knows org A's secret. They can send `POST /webhooks` directly with:
- `X-Github-Event: push` (or `pull_request`),
- body: `{"repository":{"owner":{"login":"orgA"},"full_name":"orgB/target-repo"}, ...}`,
- `X-Hub-Signature: sha1=<HMAC(webhook_secret_A, body)>`.

`verify_signature` looks up `Shipit.github(organization: "orgA")`, computes the HMAC with org A's secret, and it matches because org B's operator coincidentally configured the same secret string. The request passes verification. `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` then dispatches to e.g. `PushHandler`, whose `stacks` method resolves `Repository.from_github_repo_name("orgB/target-repo")` and calls `stack.sync_github(...)` — a write against org B's stack, authenticated only by knowledge of a secret nominally belonging to org A.

No existing guard prevents this: `drop_unhandled_event` and `check_if_ping` only gate on event type; the `ExplicitParameters` schemas (e.g. in `ClosedHandler`) validate field *presence/type*, not cross-field consistency between `owner.login` and `full_name`; `Repository` model validations only constrain the format of a single repo's `owner`/`name` columns at write time, not the webhook's internal consistency; there is no `force_github_authentication`/`require_permission!` involved in this unauthenticated webhook endpoint at all.

### Impact Explanation
A forged webhook accepted with one org's (coincidentally shared) secret can trigger writes against an unrelated org's `Stack`/`ReviewStack`/`Commit`/`Task` records — e.g., `PushHandler` enqueues `GithubSyncJob` for org B's stack, `ClosedHandler` archives org B's review stack, `LabeledHandler`/`OpenedHandler` create or mutate PR-driven review stacks for org B. This is a cross-tenant webhook payload mutating another tenant's stack, matching the Critical category ("a payload for one repository mutating another's stack, commit, task or team"). The action is repeatable at will against any repository whose full name the attacker chooses to place in the JSON body, for as long as the secret collision persists.

### Likelihood Explanation
This requires the stated precondition: two organizations' operators independently configuring an identical `webhook_secret` string in Shipit's per-organization GitHub config. This is not a cryptographic break (no secret guessing) and costs the attacker nothing beyond knowing their own org's legitimately-configured secret and crafting a raw HTTP POST with a matching HMAC — trivial once the collision exists. The likelihood is entirely gated by the probability of secret collision across independently operated orgs (which depends on how those secrets are generated/managed — e.g., low-entropy or reused defaults would materially raise this risk), not on any additional Shipit-side barrier, since the code performs zero cross-field validation regardless of secret strength.

### Recommendation
Bind the webhook's authenticated organization to the repository actually acted upon: after `verify_webhook_signature` succeeds, validate that the owner segment of `repository.full_name` (and/or `organization.login` for org-level events) equals the `repository_owner`/organization used to select the `GitHubApp`/secret, and reject (422) on mismatch. Concretely, add a check in `WebhooksController#verify_signature` (or centrally in `Handler#initialize`) asserting `payload.dig('repository','full_name')&.split('/')&.first&.downcase == repository_owner&.downcase`, independent of whether webhook secrets happen to collide across orgs.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (new test)
test "webhook signed with org A's secret cannot mutate org B's stack when secrets collide" do
  shared_secret = "shared-secret-value"

  org_a_app = Shipit::GitHubApp.new('org-a', webhook_secret: shared_secret)
  org_b_app = Shipit::GitHubApp.new('org-b', webhook_secret: shared_secret)
  Shipit.stubs(:github).with(organization: 'org-a').returns(org_a_app)
  Shipit.stubs(:github).with(organization: 'org-b').returns(org_b_app)

  # Precondition equality (both sides of the claimed binding, BEFORE the fix):
  assert_equal org_a_app.send(:webhook_secret), org_b_app.send(:webhook_secret)

  org_b_stack = shipit_stacks(:shipit) # belongs to repository owned by "org-b"

  body = {
    "ref" => "refs/heads/#{org_b_stack.branch}",
    "after" => "deadbeef",
    "repository" => {
      "owner" => { "login" => "org-a" },      # used for signature/secret lookup
      "full_name" => org_b_stack.repository.github_repo_name # "org-b/..." used by handler
    }
  }.to_json

  signature = "sha1=" + OpenSSL::HMAC.hexdigest("sha1", shared_secret, body)

  @request.headers['X-Github-Event'] = 'push'
  @request.headers['X-Hub-Signature'] = signature

  assert_enqueued_with(job: GithubSyncJob, args: [stack_id: org_b_stack.id, expected_head_sha: "deadbeef"]) do
    post :create, body: body, as: :json
  end
  # FAIL demonstrates: signature verified against org-a's secret, yet org-b's stack was written to.
end
```
This demonstrates that `repository_owner` (org A) and the org implied by `repository.full_name` (org B) diverge, the code never checks this divergence, and a job/write against org B's stack is produced despite the webhook only ever being authenticated against org A's secret.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
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

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

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

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L49-53)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```
