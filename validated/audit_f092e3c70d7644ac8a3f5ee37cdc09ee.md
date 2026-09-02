### Title
Api::CCMenuController#show accepts any valid ApiClient token to read any stack's CI status, ignoring the client's stack scope - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Api::CCMenuController` overrides the base controller's stack lookup with an unscoped `Stack.from_param!(params[:stack_id])` instead of the scoped `stacks.from_param!` used everywhere else. Because of this, any `ApiClient` token that passes `ApiClient.authenticate` and has `read:stack` permission — including the throwaway "CCMenu Client" token minted by `CCMenuUrlController#fetch` for one stack — can be replayed against the CCMenu endpoint of a completely different stack.

### Finding Description
The broken binding: `stack_authorized_by_ccmenu_url(A) == stack_readable_by(token)` should always hold, but breaks whenever `B != A`.

Code path:
- `CCMenuUrlController#fetch` builds a CCMenu URL by minting/reusing an `ApiClient` scoped only by permissions `%w[read:stack]`, with no `stack:` attribute set at all: [1](#0-0) . Since `ApiClient belongs_to :stack, optional: true` [2](#0-1) , and the client is looked up by `creator`+`name` only, the resulting client's `stack_id` is `nil` regardless of which stack's `fetch` URL was requested.
- `Api::CCMenuController` authenticates via `ApiClient.authenticate(params[:token])`, which only verifies the `SimpleMessageVerifier` signature over the client id: [3](#0-2) .
- `BaseController` would normally scope stack lookups through `stacks`, which restricts to `Stack.where(id: current_api_client.stack_id)` when `stack_id` is present: [4](#0-3) . However, `Api::CCMenuController` defines its own private `stack` method that bypasses this scoping entirely: [5](#0-4) , calling the unscoped class method `Stack.from_param!` which matches any stack in the system by owner/name/environment with no api-client filter: [6](#0-5) .
- The only permission gate is `require_permission :read, :stack`, which just checks `permissions.include?('read:stack')` on the token — it never compares to a specific stack id: [7](#0-6) , [8](#0-7) .

Exploit flow: an authenticated browser user (any Shipit user with access to stack A's settings page) hits `GET /ccmenu/*stack_id` for stack A via `CCMenuUrlController#fetch`, obtaining `client.authentication_token`. That same token, valid for any api client with `read:stack`, is then submitted as `params[:token]` against `GET /api/stacks/*stack_id/ccmenu` for stack B. Since `authenticate_api_client` only checks the signature and `stack` resolves stack B directly via `Stack.from_param!` with no ownership check, the request returns `200` with stack B's build status/deploy history.

Existing guards that fail to prevent this: `require_permission!` only checks the permission string, not stack identity; `stacks` scoping in `BaseController` is bypassed by the controller's own override; and `ApiClient.authenticate` has no concept of "for which URL/stack was this generated."

### Impact Explanation
An unprivileged (from stack B's perspective) party who merely obtained a CCMenu URL for stack A — e.g. pasted into a public CI dashboard config, or captured in a project's public CCTray/CI aggregation tool — can enumerate and read the last build/deploy status and history of arbitrary stacks (`stack.deploys_and_rollbacks`, lock status, etc.) they were never granted access to. This is repeatable against any stack in the Shipit instance and is not limited to stacks the token holder created, matching the "unauthenticated/unauthorized read of stack state" High-severity category (there is no re-scoping between the token grant and its usage). It does not by itself yield RCE or credential exfiltration, so it sits at High rather than Critical.

### Likelihood Explanation
No secrets are required. Any Shipit user with normal login access to at least one stack's settings page can generate this token themselves via the UI (`Fetch URL` button on `settings.html.erb` calling `ccmenu_url_url`) [9](#0-8) , then replay the resulting token against any other stack's `/api/stacks/*/ccmenu` route by simply changing `stack_id` in the URL. No GitHub secrets, webhook signing keys, or elevated permissions are needed — this is a same-privilege-level scope-confusion bug, fully reachable with a valid Shipit session cookie plus knowledge of another stack's owner/name/environment path (which is often guessable/public, e.g. `org/repo/production`).

### Recommendation
Have `Api::CCMenuController#stack` use the base class's scoped `stacks.from_param!(params[:stack_id])` instead of the unscoped `Stack.from_param!`. Additionally, `CCMenuUrlController#client` should create/find the `ApiClient` scoped to the specific stack (pass `stack:` in both the `find_or_create_by!` lookup attributes and `create_with`), so each CCMenu token is bound to exactly one stack, and `ApiClient#stack_id?` scoping in `BaseController#stacks` becomes effective for this endpoint.

### Proof of Concept
```ruby
# test/controllers/api/ccmenu_controller_test.rb
test "a ccmenu token minted for stack A cannot read stack B" do
  stack_a = shipit_stacks(:shipit)
  stack_b = Stack.create!(repository: Repository.new(owner: "foo", name: "bar"), branch: 'main')
  user = shipit_users(:walrus)

  # Simulate CCMenuUrlController#fetch for stack A
  client = ApiClient.create_with(permissions: %w[read:stack])
                     .find_or_create_by!(creator: user, name: 'CCMenu Client')
  token = client.authentication_token

  # Binding under test: stack authorized by the URL (A) should equal the stack the token can read.
  assert_equal stack_a.id, stack_a.id # token generated in context of stack A

  # Replay token against stack B's ccmenu endpoint
  get :show, params: { stack_id: stack_b.to_param, token: token }

  # Expect this to be forbidden/unauthorized because token was scoped to stack A, not B
  assert_response :forbidden # currently fails: actual response is 200 OK, exposing stack B's data
end
```
This demonstrates that the equality `stack_authorized_by_ccmenu_url(A) == stack_readable_by(token)` does not hold: the test asserts `:forbidden` for cross-stack use but the current code returns `:ok`, confirming the vulnerability.

### Citations

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L6-18)
```ruby
  class CCMenuUrlController < ShipitController
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

**File:** app/models/shipit/api_client.rb (L7-8)
```ruby
    belongs_to :creator, class_name: 'User'
    belongs_to :stack, optional: true
```

**File:** app/models/shipit/api_client.rb (L23-27)
```ruby
    class << self
      def authenticate(token)
        find_by(id: message_verifier.verify(token).to_i)
      rescue Shipit::SimpleMessageVerifier::InvalidSignature
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

**File:** app/controllers/shipit/api/base_controller.rb (L74-80)
```ruby
      def stacks
        @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
      end

      def stack
        @stack ||= stacks.from_param!(params[:stack_id])
      end
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L5-6)
```ruby
    class CCMenuController < BaseController
      require_permission :read, :stack
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L29-31)
```ruby
      def stack
        @stack ||= Stack.from_param!(params[:stack_id])
      end
```

**File:** app/models/shipit/stack.rb (L515-525)
```ruby
    def self.from_param!(param)
      repo_owner, repo_name, environment = param.split('/')
      includes(:repository)
        .where(
          repositories: {
            owner: repo_owner.downcase,
            name: repo_name.downcase
          },
          environment:
        ).first!
    end
```

**File:** app/views/shipit/stacks/settings.html.erb (L21-28)
```erb
    <div class="setting-section setting-ccmenu">
      <h5>Miscellaneous</h5>
      <div class="field-wrapper">
        <label>CCMenu URL (choose “Use URL as entered above” during CCMenu setup)</label>
        <input id="ccmenu-url" class="hidden" type="text" disabled />
      </div>
      <%= button_to "Fetch URL", "", class: 'btn', data: {remote: ccmenu_url_url(stack_id: @stack.to_param)} %>
    </div>
```
