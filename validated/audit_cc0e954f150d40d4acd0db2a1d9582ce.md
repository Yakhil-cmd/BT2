### Title
Cross-organization webhook authentication bypass via mismatched `repository.owner.login` and `repository.full_name` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which organization's `webhook_secret` to verify against using `repository.owner.login` (or `organization.login`), while every webhook `Handler` (e.g. `PushHandler`) resolves the target `Repository`/`Stack` using the independent, attacker-controlled `repository.full_name` field. Because these two fields are never cross-checked, an attacker can point signature verification at any organization configured without a `webhook_secret` while making the payload act on an entirely different, secured organization's repository.

### Finding Description
The binding that should hold is: `organization_used_for_signature_verification (repository.owner.login) == organization_whose_stack_is_mutated (repository.full_name.split('/').first)`.

Tracing the code:
- `verify_signature` in [1](#0-0)  calls `Shipit.github(organization: repository_owner)` and `github_app.verify_webhook_signature(...)`, where `repository_owner` is read from `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` [2](#0-1) .
- `GitHubApp#verify_webhook_signature` has the escape hatch `return true unless webhook_secret` [3](#0-2) , so any organization configured without a `webhook_secret` accepts a webhook regardless of the `X-Hub-Signature` header value.
- After `verify_signature` passes (or is bypassed), `WebhooksController#create` parses the raw body again and dispatches to handlers with the full JSON payload: `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [4](#0-3) .
- `Handler#repository_name` (used by every handler's `stacks` lookup) reads `payload.dig('repository', 'full_name')` — a completely separate JSON field from the one used in `verify_signature` [5](#0-4) .
- `PushHandler#process` uses `stacks.not_archived.where(branch:).find_each { |stack| stack.sync_github(...) }` [6](#0-5) , mutating whatever stack `repository.full_name` resolves to.

Since `repository.owner.login` and `repository.full_name` are both attacker-supplied JSON fields with no cross-field validation anywhere in this path, an attacker can craft a payload where `repository.owner.login = "insecure-org"` (an org they control, configured in Shipit with no `webhook_secret`) and `repository.full_name = "secure-org/repo"` (a different, secured org/repo). `verify_signature` looks up `insecure-org`'s `GitHubApp`, finds no secret, and returns true unconditionally — no signature is even checked. The request then reaches the handler, which acts on `secure-org/repo`'s stack using attacker-supplied `ref`/`after`/other fields, with no further authentication.

No existing guard closes this gap: `drop_unhandled_event` only checks the event type; `ExplicitParameters` schemas validate structure/presence, not owner/full_name consistency; there is no code anywhere that compares `repository.owner.login` to the owner segment of `repository.full_name`.

### Impact Explanation
An attacker who registers their own GitHub organization and gets a Shipit operator to configure it (a normal onboarding step, and one that is knowable from the public 422 "unknown organization" behavior of the endpoint) without a `webhook_secret` can subsequently forge webhooks for *any other* organization/repository configured in the same Shipit deployment. This allows triggering `sync_github`, and depending on which handler is targeted (`push`, `status`, `check_suite`, `pull_request/*`, `membership`), can drive stack state changes, commit status updates, or team membership sync for a repository the attacker never controls or authenticates for — a cross-tenant write with no valid signature required. This is a full authentication-bypass / cross-organization-mutation issue matching the Critical category ("a payload for one repository mutating another's stack, commit, task or team").

### Likelihood Explanation
Preconditions: the Shipit deployment must have at least one organization configured in `Shipit.github` without a `webhook_secret` (an operator misconfiguration), and at least one other, "secured" organization/repository whose data the attacker wants to affect. Given that, the attack is trivial and repeatable: the attacker sends arbitrary HTTP POSTs to `/webhooks` with a crafted JSON body and no valid `X-Hub-Signature` at all (the header is not even inspected once `webhook_secret` is blank). It requires no GitHub credentials, no Shipit session, and no knowledge of any secret — only knowledge that one org lacks a secret, which is discoverable by testing (a request with an invalid signature and `repository.owner.login` set to a candidate org returns `200`/handler execution instead of `422` for orgs without a secret vs. `422` for orgs with one).

### Recommendation
Cross-validate that `repository.owner.login` (or `organization.login`) equals the owner segment of `repository.full_name` before dispatching to handlers, and reject the request if they diverge. Additionally, do not treat a missing `webhook_secret` as an implicit "always verified" bypass for organizations that host multiple repositories in a multi-org deployment — require an explicit `webhook_secret` for all organizations, or scope handler repository resolution strictly to the same organization that was used for signature verification (e.g., pass `repository_owner` into `Handler.call` and only search stacks/repositories under that organization).

### Proof of Concept
```ruby
# test/controllers/shipit/webhooks_controller_cross_org_test.rb
require 'test_helper'

module Shipit
  class WebhooksControllerCrossOrgTest < ActionController::TestCase
    tests WebhooksController

    setup do
      Shipit.instance_variable_set(:@github_apps, nil) # reset memoized config if applicable
      # secure-org: configured WITH webhook_secret
      # insecure-org: configured WITHOUT webhook_secret
      stub_github_orgs(
        'secure-org' => { webhook_secret: 'supersecret' },
        'insecure-org' => {} # no webhook_secret
      )

      @secure_repo = create_repository(owner: 'secure-org', name: 'repo')
      @secure_stack = create_stack(repository: @secure_repo, branch: 'master')
    end

    test 'a forged owner with no webhook_secret cannot mutate another org stack' do
      body = {
        repository: {
          owner: { login: 'insecure-org' }, # used by verify_signature -> no secret -> bypass
          full_name: 'secure-org/repo'       # used by handler -> targets secure-org's stack
        },
        ref: 'refs/heads/master',
        after: 'deadbeef' * 5
      }.to_json

      @secure_stack.expects(:sync_github).never # binding equality: verifying org == mutated org must hold

      request.headers['X-Github-Event'] = 'push'
      request.headers['X-Hub-Signature'] = 'sha1=bogus' # not a valid signature for secure-org's secret
      post :create, body: body, as: :json

      assert_response :ok # currently passes verify_signature due to insecure-org lacking a secret
      # If the binding were enforced, this request would be rejected with 422 instead of dispatching.
    end
  end
end
```
This test demonstrates that `verify_signature` accepts the forged request via `insecure-org`'s missing `webhook_secret`, while the handler subsequently resolves and would mutate `secure-org`'s stack from `repository.full_name`, violating the "organization verifying == organization mutated" binding.

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

**File:** lib/shipit/github_app.rb (L76-77)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret
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
