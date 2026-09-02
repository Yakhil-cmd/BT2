### Title
CCMenuController bypasses the stack-scoping binding of a stack-scoped ApiClient token - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Shipit::ApiClient` tokens can be scoped to a single stack (`ApiClient#stack_id`), and `Api::BaseController#stacks`/`#stack` enforce that scope for every API endpoint that uses the shared helper. `Api::CCMenuController` overrides both `#authenticate_api_client` and `#stack`, and its override of `#stack` calls `Stack.from_param!(params[:stack_id])` directly on the unscoped `Stack` model instead of going through the scoped `stacks` collection. This breaks the binding "the stack a token authorizes" == "the stack the request touches," letting a token scoped to stack A read build/deploy status for any other stack B.

### Finding Description
`Api::BaseController` defines the authorization-scoping primitives that every API controller is supposed to use: [1](#0-0) 

`stacks` restricts the queryable set to `Stack.where(id: current_api_client.stack_id)` whenever the authenticated `ApiClient` has a `stack_id` (i.e., is scoped to a single stack), and `stack` looks up the requested resource only within that restricted set. This is the mechanism that makes `ApiClient#stack_id` a real authorization boundary, as confirmed by the test asserting a stack-scoped client "will only see that one stack": [2](#0-1) 

`Api::CCMenuController`, however, defines its own `stack` method that queries the full, unscoped `Stack` relation instead of delegating to `stacks`/`stack` from the base class: [3](#0-2) 

It also overrides `authenticate_api_client` to accept a bare `params[:token]` (for use in unauthenticated CI status URLs) but falls back to the same `ApiClient.authenticate` used elsewhere, so a stack-scoped token still authenticates successfully — it just no longer has its stack access restricted, because the controller's local `stack` method shadows the protective one in `BaseController`.

`ApiClient#check_permissions!` only checks that the permission string (e.g. `read:stack`) is present in the client's `permissions` array; it has no knowledge of `stack_id` at all: [4](#0-3) 

So the only place the `stack_id` restriction is actually enforced is the `stacks`/`stack` helper in `BaseController` — and `CCMenuController` bypasses exactly that helper.

Binding broken: `ApiClient.stack_id` (the stack a token is authorized for) ≠ `params[:stack_id]` resolved by `CCMenuController#stack` (the stack whose data is actually returned).

### Impact Explanation
An attacker who obtains (or is legitimately issued) a stack-scoped `ApiClient` token — created, for example, for embedding a CCMenu/CI status badge for one stack — can use that same token to query `GET /api/:stack_id.xml` (`CCMenuController#show`) for any other stack in the installation, retrieving that stack's latest deploy/rollback status, lock state, and build result. This is an unauthenticated-scope-widening read of stack state, matching the "unauthenticated read of stack state, task streams or deploy output" High-impact category: a token meant to be confined to one repository/stack instead discloses status information for every stack in the Shipit instance.

### Likelihood Explanation
Exploitation requires only possession of any valid `ApiClient` authentication token that has `read:stack` permission and a non-null `stack_id` — no special privilege beyond what is already granted for embedding CI badges (these tokens are commonly distributed in build-status URLs, e.g. README badges, which are inherently semi-public). No repository write access, GitHub credentials, webhook secrets, or session cookies are needed; the attacker only needs to change the `stack_id` in the request path to a stack other than the one the token was issued for. This is a straightforward URL-parameter substitution attack.

### Recommendation
Make `CCMenuController#stack` resolve through the same scoped `stacks` collection used by `BaseController` (i.e., `stacks.from_param!(params[:stack_id])`) instead of `Stack.from_param!(params[:stack_id])`, so a stack-scoped `ApiClient` token cannot read data for any stack outside its authorized `stack_id`.

### Proof of Concept
1. Create an `ApiClient` scoped to `stack_id: A` with permission `read:stack` (as done via the standard "Add API client" flow, which supports per-stack tokens for CCMenu badges).
2. Obtain the client's `authentication_token` (e.g. from the badge URL shown in stack A's settings).
3. Send `GET /api/<owner>/<repo-B>/<environment-B>.xml?token=<token>` where repo-B/environment-B is a *different* stack (B) than the one the token is scoped to.
4. `CCMenuController#authenticate_api_client` authenticates the token successfully via `ApiClient.authenticate`.
5. `CCMenuController#stack` calls `Stack.from_param!(params[:stack_id])` against the unscoped `Stack` model (not `stacks`), so it resolves stack B, and `#show` renders stack B's `deploys_and_rollbacks.last` status/lock state in the XML response — despite the token only being authorized for stack A.

### Citations

**File:** app/controllers/shipit/api/base_controller.rb (L74-80)
```ruby
      def stacks
        @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
      end

      def stack
        @stack ||= stacks.from_param!(params[:stack_id])
      end
```

**File:** test/controllers/api/stacks_controller_test.rb (L217-223)
```ruby
      test "an api client scoped to a stack will only see that one stack" do
        authenticate!(:here_come_the_walrus)
        get :index
        assert_json do |stacks|
          assert_equal 1, stacks.size
        end
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
