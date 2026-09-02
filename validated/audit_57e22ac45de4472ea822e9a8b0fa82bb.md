### Title
Failed webhook signature verification does not halt request processing, allowing unsigned/forged GitHub webhook events to be executed - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` computes whether the `X-Hub-Signature` header is valid but never stops the request pipeline when it is not, so the `create` action still runs and dispatches the (forged) payload to the registered event handlers.

### Finding Description
`verify_signature` is registered as a `before_action` and is supposed to gate `create`, the action that dispatches the parsed webhook payload to `Shipit::Webhooks.for_event(event)` handlers: [1](#0-0) 

Inside `verify_signature`, when `verified` is `false` it calls `head(422) unless verified` but never returns, halts, or throws `:abort`: [2](#0-1) 

Since Rails 5, a `before_action` only stops the remaining callback chain (and the action) if it explicitly calls `throw(:abort)`; merely calling `render`/`head` inside the filter does not prevent the controller action from subsequently executing. `head` itself just mutates the response status/body directly — it does not raise `AbstractController::DoubleRenderError`, so a second `head` call from `create` silently overwrites the earlier `422`. As a result:
- `create` still executes `JSON.parse(request.raw_post)` and calls `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` with the **unverified, attacker-controlled** payload.
- `create` then calls `head(:ok)`, which overwrites the `422` set by `verify_signature`, so the HTTP response even reports success.

This breaks the binding "payload acted on ⇔ payload covered by verified signature": the `verified` boolean computed by `github_app.verify_webhook_signature` is checked but has no enforced effect on whether `Shipit::Webhooks` handlers run.

The registered handlers are non-trivial and mutate protocol state based on the payload contents without any other authentication, e.g. `Handlers::StatusHandler#process` creates commit statuses from arbitrary `sha`/`state`/`context` fields, `Handlers::PushHandler`, and pull-request handlers: [3](#0-2) [4](#0-3) 

Commit statuses gate whether a commit is "deployable" in Shipit's deploy pipeline, so an attacker forging a `status` event (setting `state: "success"` for arbitrary commits/contexts) can flip a commit into a deployable state without ever presenting a valid webhook secret — an unauthorized/unauthenticated write influencing whether an operator's subsequent deploy is permitted.

The engine's own test suite only asserts the eventual HTTP status, not that handlers were skipped, so this control-flow gap is not caught: [5](#0-4) 

### Impact Explanation
This crosses the "payload field acted on but never covered by the verified signature" trust boundary explicitly in scope. An unauthenticated network attacker who can reach the `/webhooks` endpoint (no GitHub App private key, no `webhook_secret`, no session, and no repository write access required) can forge a webhook body and have it processed by `Shipit::Webhooks` handlers exactly as if it originated from GitHub. Depending on which handlers are registered (`status`, `push`, `pull_request`, `membership`, `check_suite`), this can create/alter commit `Status` records that gate deployability, create/close `Team`/`Membership` records, or trigger `GithubSyncJob`/review-stack workflows — state changes that influence whether a deploy is subsequently permitted, which maps to "an unauthorized deploy" in the Critical impact bucket.

### Likelihood Explanation
High. The bug requires only sending an HTTP POST to the public webhook endpoint with any `X-Github-Event` header and an arbitrary JSON body; no cryptographic secret, token, or valid signature is needed because the signature check's failure branch does not stop execution. This is a pure control-flow defect (missing `throw(:abort)`/`return` after `head(422)`), not dependent on timing, race conditions, or resource exhaustion.

### Recommendation
In `app/controllers/shipit/webhooks_controller.rb`, make `verify_signature` (and `check_if_ping`/`drop_unhandled_event`) explicitly halt the filter chain when they render a response, e.g. `head(422) and return if !verified` (or `throw(:abort) unless verified`), and add a regression test that asserts `Shipit::Webhooks.for_event` handlers are never invoked when `verify_webhook_signature` returns `false`.

### Proof of Concept
1. POST to `/webhooks` with header `X-Github-Event: status` and a body such as `{"sha":"<victim_sha>","state":"success","context":"ci/build","repository":{"owner":{"login":"<org>"}}}`, using an invalid/missing `X-Hub-Signature`.
2. `verify_signature` computes `verified = false` and calls `head(422)`, but does not halt the callback chain.
3. `create` still runs: it parses the raw body and calls `Handlers::StatusHandler#process`, which executes `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` — creating a forged successful status for the given commit despite the invalid signature.
4. `create` then calls `head(:ok)`, overwriting the earlier `422`, so the attacker even observes a `200 OK` response confirming the forged event was accepted and processed.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L6-15)
```ruby
    before_action :check_if_ping, :drop_unhandled_event, :verify_signature

    respond_to :json

    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
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
```

**File:** app/models/shipit/webhooks.rb (L6-23)
```ruby
      def default_handlers
        {
          'push' => [Handlers::PushHandler],
          'pull_request' => [
            Handlers::PullRequest::OpenedHandler,
            Handlers::PullRequest::ClosedHandler,
            Handlers::PullRequest::ReopenedHandler,
            Handlers::PullRequest::EditedHandler,
            Handlers::PullRequest::AssignedHandler,
            Handlers::PullRequest::LabeledHandler,
            Handlers::PullRequest::UnlabeledHandler,
            Handlers::PullRequest::LabelCapturingHandler
          ],
          'status' => [Handlers::StatusHandler],
          'membership' => [Handlers::MembershipHandler],
          'check_suite' => [Handlers::CheckSuiteHandler]
        }
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

**File:** test/controllers/webhooks_controller_test.rb (L94-107)
```ruby
    test "verifies webhook signature" do
      commit = shipit_commits(:first)

      payload = { "sha" => commit.sha, "state" => "pending", "target_url" => "https://ci.example.com/1000/output" }.merge(repository_params).to_json
      signature = 'sha1=4848deb1c9642cd938e8caa578d201ca359a8249'

      @request.headers['X-Github-Event'] = 'push'
      @request.headers['X-Hub-Signature'] = signature

      Shipit.github(organization: 'shopify').expects(:verify_webhook_signature).with(signature, payload).returns(false)

      post :create, body: payload, as: :json
      assert_response :unprocessable_entity
    end
```
