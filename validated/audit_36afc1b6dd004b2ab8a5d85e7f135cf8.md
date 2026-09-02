### Title
Webhook signature failure does not halt the filter chain, letting unsigned payloads be processed - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` is a `before_action` that is supposed to reject any webhook whose `X-Hub-Signature` does not match the configured `webhook_secret`. When verification fails, it calls `head(422)` but never returns/halts, so the `before_action` chain and the `create` action still run, dispatching the attacker-supplied JSON body to the registered `Shipit::Webhooks` handlers before the eventual double-render error aborts the response.

### Finding Description
`verify_signature` is invoked as a `before_action` ahead of `create`: [1](#0-0) 

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
  Rails.logger.info([...].join(' '))
rescue Shipit::GithubOrganizationUnknown => e
  head(422)
  Rails.logger.warn([...].join(' '))
end
``` [2](#0-1) 

`head(422)` marks the response as "performed" but, in Rails 5+, does not `throw(:abort)` and there is no explicit `return` after it. Because `before_action` callback halting requires an explicit abort signal (not just calling `head`/`render`), the callback method finishes normally (its last expression is `Rails.logger.info(...)`, a truthy value), so the filter chain is **not halted**. The `create` action therefore still runs and dispatches the raw, unverified JSON body to the registered handlers:
```ruby
def create
  params = JSON.parse(request.raw_post)
  Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }
  head(:ok)
end
``` [3](#0-2) 

Only the final `head(:ok)` call collides with the already-committed `head(422)` response (raising a double-render error) - but by that point the handler side effects (`PushHandler`, `Handlers::StatusHandler`, `MembershipHandler`, `CheckSuiteHandler`, pull-request handlers) have already executed with fully attacker-controlled `params`, since `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` runs before the second `head` call. This is a genuine break of the trust binding "a payload field acted on but never covered by the verified signature": the signature check exists but its failure does not stop the payload from being acted on.

### Impact Explanation
This endpoint is unauthenticated and public (no Shipit session, ApiClient token, or knowledge of `webhook_secret` is required to reach it - the attacker simply supplies any/garbage signature). Because processing continues regardless of signature validity, an anonymous attacker can forge any GitHub webhook event body Shipit understands, most critically the `status` event handled by `Handlers::StatusHandler`, which directly persists attacker-supplied `state`, `context`, `description`, and `target_url` as a `Commit::Status` for any tracked commit/repository, as shown by the existing test that populates a `Status` straight from the JSON body: [4](#0-3) 

Since Shipit's deploy safety gating (`ci.require` / `ci.blocking` statuses) relies on these `Status` records, an attacker can forge a passing CI status for a commit that never actually passed CI, enabling an **unauthorized deploy** of unreviewed/malicious code - one of the explicitly listed Critical impacts. Other handlers (`push`, `membership`, `check_suite`, `pull_request`) are similarly reachable with forged data, allowing spurious job scheduling, on-the-fly team/user creation, and stack sync triggering without any valid credential.

### Likelihood Explanation
High. The webhook endpoint is intentionally public/unauthenticated (it must accept GitHub's real webhooks), so the only barrier is signature verification - and that barrier does not actually block processing due to the missing halt. No secret knowledge, session, or account is required; the attacker only needs to know/guess the stack's repository owner/name (public information) and POST a JSON body with the right shape and any `X-Github-Event` header.

### Recommendation
Make `verify_signature` actually halt the request pipeline on failure, e.g.:
```ruby
def verify_signature
  ...
  unless verified
    head(422)
    return  # or `throw(:abort)`
  end
  ...
rescue Shipit::GithubOrganizationUnknown => e
  head(422)
  return
  ...
end
```
Additionally, consider using Rails' `render` + explicit `throw(:abort)` (or converting these filters into ones that raise and are rescued centrally) so any future filter added to this chain fails closed instead of open. Add a regression test asserting that a `push`/`status` webhook with an invalid signature results in **no** side effects (no `Status` created, no job enqueued), not just a `422` response code.

### Proof of Concept
1. Send an HTTP POST to `/webhooks` (as mounted by the engine) with:
   - `X-Github-Event: status`
   - `X-Hub-Signature: sha1=0000000000000000000000000000000000000000` (invalid/garbage signature)
   - Body: a JSON payload shaped like `test/fixtures/payloads/status_master.json` but with `state: "success"`, `context: "ci/required-check"`, and the `sha` of a real, unreviewed commit on a tracked stack's repository.
2. Because `verify_signature` fails to halt on `head(422)`, `WebhooksController#create` still executes `Shipit::Webhooks.for_event('status').each { |handler| handler.call(params) }`, invoking `StatusHandler`, which creates a `Commit::Status` record with the forged `state`/`context` for that commit (see `test/controllers/webhooks_controller_test.rb:42-59` for the code path that persists these fields directly from the payload).
3. The response ultimately raises a double-render error / returns `422`, but the `Status` row has already been persisted, satisfying the repository's CI requirement for that commit and enabling it to be deployed even though the request was never validated as coming from GitHub.

(Note: I could not execute this PoC in a live environment - I verified the code path (missing halt in the `before_action`, and handler side effects in `create`) statically from the controller and handler source and the existing test suite that exercises the `status` handler's payload-to-`Status` mapping. Full confirmation of the exact Rails-version halting semantics would benefit from running the request against a live/test instance of the engine.)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L4-16)
```ruby
  class WebhooksController < ActionController::Base
    skip_before_action :verify_authenticity_token, raise: false
    before_action :check_if_ping, :drop_unhandled_event, :verify_signature

    respond_to :json

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

**File:** test/controllers/webhooks_controller_test.rb (L42-59)
```ruby
    test ":state create a Status for the specific commit" do
      request.headers['X-Github-Event'] = 'status'

      commit = shipit_commits(:first)

      body = JSON.parse(payload(:status_master)).merge(repository_params).to_json
      assert_difference 'commit.statuses.count', 1 do
        post :create, body:, as: :json
      end

      status = commit.statuses.last
      status_payload = JSON.parse(payload(:status_master))
      assert_equal status_payload['target_url'], status.target_url
      assert_equal status_payload['state'], status.state
      assert_equal status_payload['description'], status.description
      assert_equal status_payload['context'], status.context
      assert_equal status_payload['created_at'], status.created_at.iso8601
    end
```
