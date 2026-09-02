This confirms the vulnerability. `ApiClient` has an optional `belongs_to :stack` association with a `stack_id` column [1](#0-0) , and `Api::BaseController#stacks`/`#stack` explicitly scope lookups to that stack when `stack_id` is present: `current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all` [2](#0-1) . `Api::CCMenuController` overrides `stack` to bypass this scope entirely, calling `Stack.from_param!(params[:stack_id])` unscoped [3](#0-2) .

### Title
Stack-scoped API token bypasses stack authorization in `CCMenuController#stack` - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Api::CCMenuController#stack` overrides the base controller's scope-aware stack lookup with an unscoped `Stack.from_param!(params[:stack_id])`, ignoring `current_api_client.stack_id`. Any API token that was intended to be restricted to a single stack via `ApiClient#stack_id` can be used to read CCMenu XML (deploy/task status) for any other stack in the installation.

### Finding Description
The binding that should hold: for any request through the API, `stack ∈ Stack.where(id: current_api_client.stack_id)` when `current_api_client.stack_id?` is true — i.e. `stack.id == current_api_client.stack_id`. This is enforced in `Api::BaseController#stacks`/`#stack`: `@stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all` then `stacks.from_param!(params[:stack_id])` [2](#0-1) .

`Api::CCMenuController < BaseController` redefines `stack` as `@stack ||= Stack.from_param!(params[:stack_id])`, which queries `Stack` directly with no reference to `current_api_client` at all [3](#0-2) . `require_permission :read, :stack` only checks that the token has the `read:stack` permission string via `ApiClient#check_permissions!`, which does not consult `stack_id` either [4](#0-3) . So a token with `stack_id = 1` and `permissions: ['read:stack']` passes the permission check and then is used to fetch any `params[:stack_id]` the attacker supplies, e.g. stack 2.

Attack flow: an `ApiClient` with `stack_id` set to stack A and `read:stack` permission exists (this field is settable on any `ApiClient` record, per the schema/association) [5](#0-4) . Using that client's `authentication_token`, an attacker (or the legitimate low-privilege holder of that token) requests `GET /api/stacks/:owner/:repo2/:env2/ccmenu?token=<token>`, matching the route `get '/ccmenu' => 'ccmenu#show'` under `scope '/stacks/*stack_id'` [6](#0-5) . `authenticate_api_client` accepts the token via `ApiClient.authenticate(params[:token])` [7](#0-6) , `require_permission!(:read, :stack)` passes because permissions include `read:stack`, and `show` renders stack 2's deploy/rollback XML via the unscoped `stack` method [8](#0-7) .

Existing test coverage only exercises the happy path with an unscoped client from `ApiControllerTestCase#authenticate!` and never asserts scope enforcement for CCMenu [9](#0-8) , so this divergence from `BaseController#stack` is untested and unguarded.

Note on the specific scenario in the question: the token minted by `CCMenuUrlController#fetch` itself is *not* stack-scoped — `client` is created via `ApiClient.create_with(permissions: %w[read:stack]).find_or_create_by!(creator:, name:)` with no `stack_id` set [10](#0-9) . Since that token has `stack_id` nil, it was never scoped to stack A in the first place, so it provides no representative example of the broken binding being exploited — an unscoped token being usable everywhere is expected behavior, not a bypass. However, the underlying flaw is real and general: any `ApiClient` (created through other paths, e.g. `resources :api_clients` management UI, which permits setting `stack` per the `belongs_to :stack, optional: true` association) that *is* stack-scoped will have that scope silently ignored specifically by the CCMenu endpoint, unlike every other API controller that inherits `BaseController#stack`.

### Impact Explanation
A stack-scoped `read:stack` API token — intended to restrict a client to reading state of one stack — can read CCMenu XML (deploy status, last build label/time, activity) for any other stack in the Shipit instance by simply changing `stack_id` in the URL. This matches the High-severity category "unauthorized cross-repository read of deploy/task state" / "unauthenticated read of stack state" relative to the token's intended scope, since the leak crosses the authorization boundary the `stack_id` field is meant to enforce. It is fully repeatable against arbitrary stacks by enumerating `owner/name/environment` triples, with no additional secrets required beyond possession of any valid scoped token.

### Likelihood Explanation
This requires an `ApiClient` record with a non-null `stack_id` to exist and its token to be exposed to the attacker (e.g. an integration issued via the `api_clients` management UI restricted to one stack, then leaked or held by a low-privilege user/service). Because `CCMenuUrlController#fetch` itself never creates such a scoped client, the specific attack chain described in the question (starting from that endpoint) does not actually demonstrate the vulnerability — the divergence only becomes exploitable when a stack-scoped `ApiClient` is created through another path. Given the code inconsistency exists and is trivially reachable once a scoped token exists, likelihood is moderate and depends on operator usage of scoped clients.

### Recommendation
Change `Api::CCMenuController#stack` to reuse the scope-aware lookup from the base controller, i.e. remove the override or implement it as `@stack ||= stacks.from_param!(params[:stack_id])`, matching `Api::BaseController#stack`.

### Proof of Concept
```ruby
# test/controllers/api/ccmenu_controller_test.rb
test "a stack-scoped client cannot read another stack's ccmenu xml" do
  other_stack = shipit_stacks(:cyclimse) # any stack != @stack
  @client.update!(stack_id: @stack.id, permissions: %w[read:stack])
  get :show, params: { stack_id: other_stack.to_param, token: @client.authentication_token }
  assert_response :not_found # expected: scoped out, same as Api::StacksController#show would behave
  # current behavior: assert_response :ok, and stack.id != @client.stack_id, proving the bypass
end
```
This mirrors the scoping already tested against other API endpoints that rely on `Api::BaseController#stack`, and would currently fail (return `:ok` with the other stack's XML) demonstrating `stack.id != current_api_client.stack_id` while it should be `==` or `stack_id` nil.

### Citations

**File:** app/models/shipit/api_client.rb (L7-8)
```ruby
    belongs_to :creator, class_name: 'User'
    belongs_to :stack, optional: true
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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L22-25)
```ruby
      def show
        latest_deploy = stack.deploys_and_rollbacks.last || NoDeploy.new
        render('shipit/ccmenu/project', formats: [:xml], locals: { stack:, deploy: latest_deploy })
      end
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L29-31)
```ruby
      def stack
        @stack ||= Stack.from_param!(params[:stack_id])
      end
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L33-36)
```ruby
      def authenticate_api_client
        @current_api_client = ApiClient.authenticate(params[:token])
        super unless @current_api_client
      end
```

**File:** config/routes.rb (L27-29)
```ruby
    scope '/stacks/*stack_id', stack_id: stack_id_format, as: :stack do
      get '/ccmenu' => 'ccmenu#show', as: :ccmenu
      resource :lock, only: %i[create update destroy]
```

**File:** test/controllers/api/ccmenu_controller_test.rb (L8-24)
```ruby
      setup do
        authenticate!
        @stack = shipit_stacks(:shipit)
      end

      test "a request with insufficient permissions will render a 403" do
        @client.update!(permissions: [])
        get :show, params: { stack_id: @stack.to_param }
        assert_response :forbidden
        assert_json 'message', 'This operation requires the `read:stack` permission'
      end

      test "#show renders the xml" do
        get :show, params: { stack_id: @stack.to_param }
        assert_response :ok
        assert_payload 'name', @stack.to_param
      end
```

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L15-18)
```ruby
    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```
