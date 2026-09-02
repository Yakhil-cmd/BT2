Confirmed - default `Shipit.disable_api_authentication` is `false` (only overridden in the dummy app's development environment for local testing), so production API reads require the basic-auth/token check.

### Title
No vulnerability - `Api::BaseController#authenticate_api_client` still gates `Api::StacksController#show` regardless of `StatusHandler` forgery - (File: `app/controllers/shipit/api/base_controller.rb`)

### Summary
The binding under test is: `Api::BaseController` requires a valid `ApiClient` token on every action (via `before_action :authenticate_api_client`) == unauthenticated requests always receive `401`. Tracing the code confirms this binding is untouched by the cross-repo `StatusHandler` forgery bug; there is no code path in `Api::StacksController` or `StatusHandler` that skips or weakens this check.

### Finding Description
`Api::BaseController` registers `before_action :authenticate_api_client` unconditionally for all subclasses/actions [1](#0-0) . `authenticate_api_client` requires HTTP Basic credentials that resolve via `ApiClient.authenticate(token)`, or immediately renders `401 Bad credentials` and returns [2](#0-1) . This check is bypassed only when `Shipit.disable_api_authentication` is true, which is a Shipit-operator-controlled config flag not reachable by an unprivileged attacker (it is set only in the test dummy app's development environment, not in production defaults) [3](#0-2) [4](#0-3) .

`Api::StacksController#show` additionally requires `require_permission :read, :stack, only: %i[index show]`, which runs `current_api_client.check_permissions!(operation, scope)` as a further `before_action` layered on top of the base authentication check [5](#0-4) [6](#0-5) .

`StatusHandler#process` (the component that lets an attacker-controlled webhook forge cross-repo status writes) operates entirely at the model/webhook layer — it creates `Status` records against a `Commit` looked up by SHA — and has no interaction with the `Api::BaseController` authentication chain, no session, and no `ApiClient` object. Nothing in that write path issues a token, disables `authenticate_api_client`, or otherwise opens a read side-channel. `Commit#deployable?` being falsely `true` after the forged status only affects what an *already-authorized* API client or UI user subsequently *sees* rendered (e.g. in `render_resource(stack)`); it does not change who is allowed to make the request.

Both sides of the equality are unchanged before and after the forged status: an unauthenticated request to `Api::StacksController#show` returns `401` before the attack, and still returns `401` after the attack, exactly as covered by the existing test `"authentication is required"` [7](#0-6) .

### Impact Explanation
None. No unauthenticated read is opened. The attacker gains nothing beyond what the core cross-repo mutation finding already grants (write/mutation of `deployable?`-adjacent state via forged status); no additional read-side-channel or authentication bypass exists in `Api::StacksController` or elsewhere in the `Api::` namespace as a consequence of `StatusHandler`.

### Likelihood Explanation
N/A — no exploitable divergence found.

### Recommendation
No fix required for this specific bounding question. (The underlying cross-repo write finding, if valid, should be remediated separately in `StatusHandler`/commit-lookup scoping, not here.)

### Proof of Concept
Minitest (illustrative, matches existing pattern in `test/controllers/api/base_controller_test.rb` and `test/controllers/api/stacks_controller_test.rb`):
```ruby
test "#show still requires authentication even after a forged StatusHandler-driven deployable? change" do
  stack = shipit_stacks(:shipit)
  commit = stack.commits.last

  # Simulate the forged cross-repo status write (core finding), independent of this test's auth check.
  StatusHandler.new(stub_payload_for_forged_status(commit)).process
  assert commit.reload.deployable? # state changed by the write-side bug

  # No ApiClient credentials set on this request.
  get :show, params: { id: stack.to_param }

  assert_response :unauthorized
  assert_equal({ message: 'Bad credentials' }.to_json, response.body)
end
```
Both sides of the binding hold: `authenticate_api_client` still executes as a `before_action` and still returns `401` for the unauthenticated request, unaffected by the mutated `deployable?` value.

### Citations

**File:** app/controllers/shipit/api/base_controller.rb (L24-24)
```ruby
      before_action :authenticate_api_client
```

**File:** app/controllers/shipit/api/base_controller.rb (L48-61)
```ruby
      def authenticate_api_client
        @current_api_client = if Shipit.disable_api_authentication
                                UnlimitedApiClient.new
                              else
                                BasicAuth.authenticate(request) do |*parts|
                                  token = parts.select(&:present?).join('--')
                                  ApiClient.authenticate(token)
                                end
                              end
        return if @current_api_client

        headers['WWW-Authenticate'] = 'Basic realm="Authentication token"'
        render(status: :unauthorized, json: { message: 'Bad credentials' })
      end
```

**File:** app/controllers/shipit/api/base_controller.rb (L82-84)
```ruby
      def require_permission!(operation, scope)
        current_api_client.check_permissions!(operation, scope)
      end
```

**File:** test/dummy/config/environments/development.rb (L1-1)
```ruby
Rails.application.configure do
```

**File:** app/controllers/shipit/api/stacks_controller.rb (L6-6)
```ruby
      require_permission :read, :stack, only: %i[index show]
```

**File:** test/controllers/api/base_controller_test.rb (L8-12)
```ruby
      test "authentication is required" do
        get :index
        assert_response :unauthorized
        assert_equal({ message: 'Bad credentials' }.to_json, response.body)
      end
```
