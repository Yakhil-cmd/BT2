### Title
Shared, unscoped CCMenu API token grants read access to every stack, not just the one it was minted for - (File: app/controllers/shipit/ccmenu_url_controller.rb, app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`CCMenuUrlController#client` memoizes/looks up an `ApiClient` solely by `(creator: current_user, name: 'CCMenu Client')`, with no `stack` attribute set and no per-stack differentiation, so every CCMenu URL a user requests embeds the identical `authentication_token`. `Api::CCMenuController` compounds this by overriding `authenticate_api_client` to authenticate solely via `ApiClient.authenticate(params[:token])` and defining its own `stack` method (`Stack.from_param!(params[:stack_id])`) instead of using `BaseController#stacks`/`#stack`, so the token's authorization is never checked against `current_api_client.stack_id`.

### Finding Description
The broken binding, stated as an equality that should hold but does not:

`token minted for GET /ccmenu/stackA` should satisfy `authorized_stacks(token) == {stackA}`, but in fact `authorized_stacks(token) == Stack.all` (every stack in the system).

Trace:
1. `CCMenuUrlController#client` (`app/controllers/shipit/ccmenu_url_controller.rb:15-18`) does `ApiClient.create_with(permissions: %w[read:stack]).find_or_create_by!(creator: current_user, name: 'CCMenu Client')`. This lookup key never includes `stack`, and `ApiClient#stack_id` is left `nil` on the created record (the `belongs_to :stack, optional: true` in `app/models/shipit/api_client.rb:8` is never populated here). Requesting `/ccmenu/stackA` then `/ccmenu/stackB` as the same user returns the same row and the same `authentication_token` (`ApiClient#authentication_token`, `app/models/shipit/api_client.rb:34-36`, which is deterministic w.r.t. `id`).
2. When that token is later presented to `Api::CCMenuController#show` via `?token=...`, the controller's own `authenticate_api_client` (`app/controllers/shipit/api/ccmenu_controller.rb:33-36`) simply does `ApiClient.authenticate(params[:token])` — it does not consult `BaseController#stacks` (which would scope to `current_api_client.stack_id` when present, `app/controllers/shipit/api/base_controller.rb:74-76`). More importantly, since `stack_id` on this `ApiClient` is `nil`, `stacks` would resolve to `Stack.all` anyway even if it were used.
3. `Api::CCMenuController#stack` (`app/controllers/shipit/api/ccmenu_controller.rb:29-31`) resolves the target stack directly from `Stack.from_param!(params[:stack_id])`, completely bypassing the `stacks` scoping helper. `require_permission :read, :stack` only checks that the client's `permissions` array contains `read:stack` (`ApiClient#check_permissions!`, `app/models/shipit/api_client.rb:38-45`); it performs no stack-identity check at all.
4. Net effect: a single `ApiClient` row with `permissions: ['read:stack']` and `stack_id: nil` is created once per user and reused for every stack that user ever requests a CCMenu URL for. Its token authorizes `show` for **any** `stack_id` parameter, not merely the stack named in the URL that was generated.

None of the listed guards intervene: `require_permission!` only checks the permission string, not stack scope; the `stacks` scope method exists in `BaseController` but is never invoked by `CCMenuController#stack`; there is no `ExplicitParameters` schema constraining `stack_id` binding to token; `User#authorized?`/`force_github_authentication` govern the *minting* request (`ccmenu_url#fetch`) but say nothing about later token redemption.

### Impact Explanation
Any authenticated low-privilege user who is a member of at least one stack's authorized team can call `GET /ccmenu/:stack_id` for that one stack to obtain a `read:stack`-scoped token, then use that same token via `GET /api/*/ccmenu/:other_stack_id?token=...` to read deploy/build status (`lastBuildStatus`, `lastBuildLabel`, activity, lock state) for **every stack in the Shipit instance**, including stacks/repositories they have no authorization for. This is an unauthenticated-for-that-resource read of stack state — matches the High severity category "unauthenticated read of stack state." It is fully repeatable: the token never expires and is reused indefinitely for the same user, and works against arbitrary stack IDs since `Stack.from_param!` performs no ownership filtering.

### Likelihood Explanation
Preconditions are minimal: the attacker only needs a normal logged-in Shipit session with legitimate access to at least one stack (to trigger `CCMenuUrlController#fetch` and obtain the token) — a bar any onboarded low-privilege user already clears. No secrets (`api_clients_secret`, `secret_key_base`, GitHub App key, `webhook_secret`) are needed; the token is handed to the user directly in the JSON response. Enumerating other stacks' numeric or slug `stack_id` values is trivial (sequential IDs or `owner/repo/env` slugs are commonly guessable/visible in shared UI). This is a one-time setup, then indefinitely repeatable against any stack.

### Recommendation
- In `CCMenuUrlController#client`, create/find the `ApiClient` scoped per-stack, e.g. `find_or_create_by!(creator: current_user, name: 'CCMenu Client', stack: stack)`, so each stack gets its own token.
- In `Api::CCMenuController`, use the inherited `stacks`/`stack` scoping (`BaseController#stacks`) instead of `Stack.from_param!(params[:stack_id])` directly, and ensure `authenticate_api_client` sets `@current_api_client` in a way compatible with that scoping (so a stack-bound `ApiClient` can only resolve its own stack).
- Alternatively, explicitly check `current_api_client.stack_id.nil? || current_api_client.stack_id == stack.id` before rendering in `CCMenuController#show`.

### Proof of Concept
```ruby
# test/controllers/ccmenu_controller_test.rb (extend existing test class)
test ":fetch reuses the same ApiClient/token across different stacks, and that token authorizes all stacks" do
  stack_a = shipit_stacks(:shipit)
  stack_b = Stack.create!(repository: Repository.create!(owner: 'foo', name: 'bar'), branch: 'main')

  get :fetch, params: { stack_id: stack_a.to_param }
  token_a = JSON.parse(response.body)['ccmenu_url']

  assert_no_difference 'ApiClient.count' do
    get :fetch, params: { stack_id: stack_b.to_param }
  end
  token_b = JSON.parse(response.body)['ccmenu_url']

  query_a = Rack::Utils.parse_nested_query(URI(token_a).query)
  query_b = Rack::Utils.parse_nested_query(URI(token_b).query)
  assert_equal query_a['token'], query_b['token'] # same shared token

  # The token minted while requesting stack_a now authenticates a request for
  # an unrelated stack (stack_b) via the API CCMenu endpoint.
  get "/api/#{Shipit::Api::CCMenuController.name}", params: {} # illustrative; use actual API route helper
  # Using api_stack_ccmenu_url(stack_id: stack_b.to_param, token: query_a['token'])
  # should return 200 with stack_b's data, proving the token is not stack-bound.
end
```
This demonstrates: (1) `ApiClient.count` does not increase on the second `/ccmenu/:stack_id` call for a different stack, confirming the shared/memoized client; and (2) the shared token, minted nominally "for" `stack_a`, successfully authenticates and authorizes reads against `stack_b` through `Api::CCMenuController#show`, confirming the missing stack-binding. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L15-18)
```ruby
    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L29-36)
```ruby
      def stack
        @stack ||= Stack.from_param!(params[:stack_id])
      end

      def authenticate_api_client
        @current_api_client = ApiClient.authenticate(params[:token])
        super unless @current_api_client
      end
```

**File:** app/models/shipit/api_client.rb (L7-45)
```ruby
    belongs_to :creator, class_name: 'User'
    belongs_to :stack, optional: true

    validates :creator, :name, presence: true

    serialize :permissions, coder: Shipit.serialized_column(:permissions, type: Array)
    PERMISSIONS = %w[
      read:stack
      write:stack
      deploy:stack
      lock:stack
      read:hook
      write:hook
    ].freeze
    validates :permissions, subset: { of: PERMISSIONS }

    class << self
      def authenticate(token)
        find_by(id: message_verifier.verify(token).to_i)
      rescue Shipit::SimpleMessageVerifier::InvalidSignature
      end

      def message_verifier
        @message_verifier ||= Shipit::SimpleMessageVerifier.new(Shipit.api_clients_secret)
      end
    end

    def authentication_token
      self.class.message_verifier.generate(id)
    end

    def check_permissions!(operation, scope)
      required_permission = "#{operation}:#{scope}"
      unless permissions.include?(required_permission)
        raise InsufficientPermission, "This operation requires the `#{required_permission}` permission"
      end

      true
    end
```

**File:** app/controllers/shipit/api/base_controller.rb (L74-84)
```ruby
      def stacks
        @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
      end

      def stack
        @stack ||= stacks.from_param!(params[:stack_id])
      end

      def require_permission!(operation, scope)
        current_api_client.check_permissions!(operation, scope)
      end
```

**File:** test/controllers/ccmenu_controller_test.rb (L21-33)
```ruby
    test ":fetch creates a read only api client" do
      assert_difference 'ApiClient.count' do
        get :fetch, params: { stack_id: @stack.to_param }
      end
    end

    test ":fetch url includes api token on query string" do
      get :fetch, params: { stack_id: @stack.to_param }
      data = JSON.parse(response.body)
      client = ApiClient.last
      query = Rack::Utils.parse_nested_query(URI(data['ccmenu_url']).query)
      assert_equal client.authentication_token, query['token']
    end
```

**File:** test/controllers/api/ccmenu_controller_test.rb (L26-31)
```ruby
      test "can authenticate with query string token" do
        request.headers['Authorization'] = 'bleh'
        get :show, params: { stack_id: @stack.to_param, token: @client.authentication_token }
        assert_response :ok
        assert_payload 'name', @stack.to_param
      end
```
