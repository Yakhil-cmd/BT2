### Title
CCMenu API token scoped to one stack can be replayed to read build status of any stack - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Api::CCMenuController` accepts unauthenticated, token-based access (no session cookie required) but resolves the target `Stack` without checking that the presented `ApiClient` token is actually scoped to that stack. This breaks the intended binding "the stack a token authorizes" == "the stack the token is used against."

### Finding Description
`CCMenuUrlController#client` mints (or reuses) an `ApiClient` per-user, named `'CCMenu Client'`, with the `read:stack` permission, but it is created **without** a `stack:` association: [1](#0-0) 

The generated URL simply embeds this stack-agnostic token as a query parameter alongside a `stack_id` path segment for the stack the user was viewing: [2](#0-1) 

On the API side, `Api::BaseController` defines the correct, scoping-aware pattern used by every other endpoint: it restricts the visible stacks to `current_api_client.stack_id` when the client is stack-scoped: [3](#0-2) 

However, `Api::CCMenuController` does not use this scoped `stacks`/`stack` helper. It overrides `stack` to resolve **directly** from the request parameter with no relation to `current_api_client` at all: [4](#0-3) 

Authentication for this controller also explicitly supports a bare `?token=` query parameter with no session/cookie: [5](#0-4) 

`require_permission :read, :stack` (declared at the top of the controller) only calls `ApiClient#check_permissions!`, which checks the permission **name** string ("read:stack") — it never checks stack identity: [6](#0-5) 

So the only binding that should limit which stack a given ccmenu token can read is the `ApiClient#stack_id` association — and `CCMenuController#stack` never consults it. Any bearer of a valid ccmenu token (whether generated for a stack-scoped client or, as shown here, an unscoped one) can substitute any other stack's `stack_id` in the URL and receive that stack's CI/build status, since `Stack.from_param!(params[:stack_id])` performs no ownership check against the token.

This is the direct structural analog of the reported bug class: a value that is supposed to gate/limit an operation (the token's authorized stack) is silently never applied at the point where the operation executes (reading a specific stack's state), because the code path bypasses the check entirely rather than because of an off-by-timing arithmetic issue, but the net effect is identical — the authorization binding that should hold is never enforced.

### Impact Explanation
This is an unauthenticated (token-only, no session) read of stack state — the `show` action exposes `lastBuildStatus`, `lastBuildLabel`, `activity`, `webUrl`, and lock status for a stack: [7](#0-6) [8](#0-7) 

Any single leaked/shared ccmenu URL (these are meant to be embedded in third-party CI dashboard tools and are commonly pasted into chat, wikis, or status boards) becomes a durable, unauthenticated bearer credential granting read access to **every** stack in the Shipit instance rather than just the one it was generated for. This matches the "High — unauthenticated read of stack state" impact category.

### Likelihood Explanation
Any authenticated Shipit user can trivially obtain a ccmenu token/URL for one stack they have visibility into (via the stack settings page which calls `CCMenuUrlController#fetch`), and then simply edit the `stack_id` in the resulting URL to target other stacks. No secrets, GitHub credentials, or elevated privileges are required beyond one legitimate ccmenu URL.

### Recommendation
`Api::CCMenuController#stack` should resolve through the same client-scoped lookup used elsewhere (`stacks.from_param!(params[:stack_id])`, inheriting `Api::BaseController#stacks`'s `current_api_client.stack_id?` check), and/or `CCMenuUrlController#client` should mint the `ApiClient` with `stack:` set to the specific stack so the token is cryptographically/structurally bound to that one stack.

### Proof of Concept
1. As a normal Shipit user, visit Stack A's settings page, which triggers `CCMenuUrlController#fetch` for `stack_id=A` and returns a URL like `.../api/stacks/A/ccmenu.xml?token=T`, per: [9](#0-8) 
2. Without any session cookie, issue `GET /api/stacks/B/ccmenu.xml?token=T` for an unrelated Stack B.
3. Because `Api::CCMenuController#stack` uses `Stack.from_param!(params[:stack_id])` with no cross-check against `current_api_client.stack_id`, and `authenticate_api_client` accepts `token` from the query string directly: [10](#0-9) 
the request succeeds and returns Stack B's build status XML, even though token `T` was only ever generated/intended for Stack A.

### Citations

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L6-22)
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

    def stack
      @stack ||= Stack.from_param!(params[:stack_id])
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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L22-36)
```ruby
      def show
        latest_deploy = stack.deploys_and_rollbacks.last || NoDeploy.new
        render('shipit/ccmenu/project', formats: [:xml], locals: { stack:, deploy: latest_deploy })
      end

      private

      def stack
        @stack ||= Stack.from_param!(params[:stack_id])
      end

      def authenticate_api_client
        @current_api_client = ApiClient.authenticate(params[:token])
        super unless @current_api_client
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

**File:** test/controllers/api/ccmenu_controller_test.rb (L20-24)
```ruby
      test "#show renders the xml" do
        get :show, params: { stack_id: @stack.to_param }
        assert_response :ok
        assert_payload 'name', @stack.to_param
      end
```

**File:** test/controllers/api/ccmenu_controller_test.rb (L41-45)
```ruby
      test "locked stacks show as failed" do
        @stack.lock('test', @user)
        get :show, params: { stack_id: @stack.to_param }
        assert_payload 'lastBuildStatus', 'Failure'
      end
```
