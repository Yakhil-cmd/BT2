### Title
`CCMenuUrlController#client` mints a globally-scoped `read:stack` API token that, once leaked, grants task-output disclosure for every stack - (File: `app/controllers/shipit/ccmenu_url_controller.rb`)

### Summary
`CCMenuUrlController#fetch` embeds an `ApiClient` authentication token in a plain URL query string and hands it to the browser, but the underlying `ApiClient` (`app/controllers/shipit/ccmenu_url_controller.rb:15-18`) is created with `permissions: %w[read:stack]` and **no `stack:` association**. Because `Api::BaseController#stacks` only restricts access when `current_api_client.stack_id?` is true (`app/controllers/shipit/api/base_controller.rb:74-76`), this unscoped token authorizes `read:stack` operations against **every** stack, not just the one the CCMenu URL was generated for.

### Finding Description
The invariant the question asks to validate is:
`token.stack_id == stack.id` (or token is otherwise cryptographically bound to the specific stack) for every stack-scoped request such as `GET /api/stacks/*stack_id/tasks/:id/output`.

Tracing the code:
1. A logged-in user requests a CCMenu URL for stack A via `Shipit::CCMenuUrlController#fetch`: [1](#0-0) 
   The `client` method does `ApiClient.create_with(permissions: %w[read:stack]).find_or_create_by!(creator: current_user, name: 'CCMenu Client')` — it never sets `stack:`, so the created/found `ApiClient` record has `stack_id = nil` and permission `read:stack`, independent of which stack the URL was requested for. The generated token (`client.authentication_token`) is embedded as `?token=...` in the returned `ccmenu_url`.
2. This token is now a bearer credential good for `read:stack` on **any** stack, because `Api::BaseController#stacks`: [2](#0-1) 
   only applies `Stack.where(id: current_api_client.stack_id)` when `stack_id?` is true; for this token it is `nil`, so the scope falls through to `Stack.all`.
3. `Api::OutputsController#show` (`GET /api/stacks/*stack_id/tasks/:id/output`) only requires `read:stack` permission and pulls the stack from the (unscoped, for this token) `stacks` relation: [3](#0-2) 
   `ApiClient#check_permissions!` only checks that `"read:stack"` is in the permissions array — it performs no per-stack binding check: [4](#0-3) 
4. Basic-auth authentication in `Api::BaseController#authenticate_api_client` accepts any valid `ApiClient.authenticate(token)`, so the leaked query-string token from the CCMenu URL of stack A can be replayed as Basic-Auth credentials (or, for the `CCMenuController` route itself, directly as `?token=`) against `GET /api/stacks/B/tasks/:id/output` for an unrelated stack B, succeeding because the token was never bound to stack A in the first place.
5. Because the ccmenu URL is designed to be pasted into third-party CI-status widgets/monitors (an explicit, documented leak vector — it's a bare URL with the secret in the query string), the token is exposed via Referer headers, browser history, and server logs of whatever tool consumes it, exactly as the question describes.

Existing guards (`require_permission!`, the `stacks` scope, `ApiClient#check_permissions!`) do not prevent this because they all trust `current_api_client.stack_id`, which is simply never populated by `CCMenuUrlController#client`.

### Impact Explanation
Any user able to request a CCMenu URL for one stack (a normal, low-privilege UI feature) obtains a durable bearer token that discloses deploy/task output for **every stack in the Shipit instance**, not just the one requested. This is an unauthenticated-read-style disclosure of stack state and deploy output across tenants once the token leaks (via Referer, logs, browser history, or a compromised CI dashboard that stores the ccmenu URL) — matching the "High: unauthenticated read of stack state, task streams or deploy output" impact category. The token is durable (HMAC-based, no expiry visible in `ApiClient#authentication_token`) and reusable indefinitely against arbitrary stacks.

### Likelihood Explanation
Preconditions: attacker needs the token value, which requires either (a) being the user who generated it (trivial, self-service) and then having it leak through an external channel (Referer/logs/history — realistic given the widget's design), or (b) intercepting/obtaining a leaked ccmenu URL another user generated. No GitHub or Shipit secrets are required; generating the token only requires a normal Shipit session and clicking "CCMenu URL" for any single stack the user can view. This is low-cost and repeatable.

### Recommendation
Bind the `ApiClient` created by `CCMenuUrlController#client` to the specific stack, e.g. `ApiClient.create_with(permissions: %w[read:stack], stack: stack).find_or_create_by!(creator: current_user, stack: stack, name: 'CCMenu Client')`, so `stack_id?` is true and `Api::BaseController#stacks` correctly restricts the token to `Stack.where(id: stack.id)`. Also consider giving each generated CCMenu token a unique per-stack identity rather than reusing one record per user across all stacks.

### Proof of Concept
Minitest plan (`test/controllers/ccmenu_url_controller_test.rb` + `test/controllers/api/outputs_controller_test.rb`):
```ruby
test "ccmenu token for stack A cannot read task output for stack B" do
  user = shipit_users(:walrus)
  stack_a = shipit_stacks(:shipit)
  stack_b = shipit_stacks(:cyclimse) # a different stack

  session[:user_id] = user.id
  get :fetch, params: { stack_id: stack_a.to_param }
  token = URI(JSON.parse(response.body)['ccmenu_url']).query[/token=([^&]+)/, 1]

  client = Shipit::ApiClient.find_by(name: 'CCMenu Client', creator: user)
  assert_nil client.stack_id, "token unexpectedly scoped to a single stack"

  task = shipit_tasks(:cyclimse_deploy) # belongs to stack_b, not stack_a
  get :show, params: { stack_id: stack_b.to_param, task_id: task.id },
      headers: { 'HTTP_AUTHORIZATION' => ActionController::HttpAuthentication::Basic.encode_credentials(token, '') }

  # Broken binding under test: token.stack_id (nil) != stack_b.id, yet request succeeds
  assert_response :success # demonstrates the leak; should be :not_found or :forbidden after fix
end
```
Both sides of the equality (`current_api_client.stack_id` vs. `stack_b.id`) should be asserted directly: the test should confirm `client.stack_id.nil?` (or `!= stack_b.id`) while the response nonetheless returns the output body for stack B, proving the invariant is violated.

### Citations

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L7-18)
```ruby
    def fetch
      uri = URI(api_stack_ccmenu_url(stack_id: stack.to_param))
      uri.query = { 'token' => client.authentication_token }.to_query
      render(json: { ccmenu_url: uri.to_s })
    end

    private

    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```

**File:** app/controllers/shipit/api/base_controller.rb (L74-76)
```ruby
      def stacks
        @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
      end
```

**File:** app/controllers/shipit/api/outputs_controller.rb (L1-17)
```ruby
# frozen_string_literal: true

module Shipit
  module Api
    class OutputsController < BaseController
      require_permission :read, :stack

      def show
        render(plain: task.chunk_output)
      end

      private

      def task
        @task ||= stack.tasks.find(params[:task_id])
      end
    end
```

**File:** app/models/shipit/api_client.rb (L38-45)
```ruby
    def check_permissions!(operation, scope)
      required_permission = "#{operation}:#{scope}"
      unless permissions.include?(required_permission)
        raise InsufficientPermission, "This operation requires the `#{required_permission}` permission"
      end

      true
    end
```
