### Title
CCMenu API endpoint bypasses per-token stack scoping, allowing a stack-scoped API token to read any stack's CC Menu status - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Shipit::Api::CCMenuController` overrides the `stack` accessor to call `Stack.from_param!(params[:stack_id])` directly instead of using `BaseController#stack`, which resolves stacks through the `stacks` scope. This bypass drops the enforcement that a stack-restricted `ApiClient` (one with `stack_id` set) may only access the stack it was issued for, allowing that token to be replayed against `:stack_id` values for arbitrary other stacks.

### Finding Description
The binding that should hold is: `stack.id == current_api_client.stack_id` (when `current_api_client.stack_id?` is true). In `BaseController`, this is enforced structurally: `stacks` returns `Stack.where(id: current_api_client.stack_id)` when the client is scoped, and `stack` calls `stacks.from_param!(params[:stack_id])`, so a scoped token requesting a foreign stack ID raises `ActiveRecord::RecordNotFound`. [1](#0-0) 

`CCMenuController` redefines `stack` to bypass this entirely: [2](#0-1) 

It also overrides `authenticate_api_client` to accept the token via the `token` query parameter (needed for CCTray clients that can't send Basic Auth headers), but this override does not reintroduce any per-stack check: [3](#0-2) 

The only authorization gate applied via `require_permission :read, :stack` is `check_permissions!`, which only checks the client's `permissions` array (e.g., `read:stack`) — it has no notion of which specific stack: [4](#0-3) 

Route: `GET /api/stacks/*stack_id/ccmenu` maps `stack_id` to any value matching the stack id format, independent of the client. [5](#0-4) 

Exploit flow: an operator issues an `ApiClient` scoped to stack A (`stack_id: stack_a.id`) intending the token to only render stack A's CC Menu XML (e.g., embedded in a public CI badge/URL, as intended by `ccmenu_url_controller.rb`/settings page). An attacker who obtains that URL/token (a legitimately shared link) can request `GET /api/stacks/<stack_b_full_path>/ccmenu.xml?token=<token>`. `authenticate_api_client` verifies the token signature and loads the `ApiClient` (still valid, still has `read:stack` permission), then `stack` resolves stack B directly via `Stack.from_param!`, ignoring `current_api_client.stack_id`. The controller renders stack B's latest deploy/rollback status without ever comparing `stack.id` to `current_api_client.stack_id`. Existing guards (`require_permission`, `check_permissions!`, `verify_signature` on the token) do not catch this because they check *token validity and generic permission* only, not *stack binding*.

### Impact Explanation
The attacker obtains unauthenticated cross-tenant read access to any stack's current deploy/rollback status (running/success/failure, last commit, timestamps) by reusing a token that was only ever meant to be valid for one stack. This is repeatable against arbitrary stacks by simply varying `:stack_id` in the URL, requiring only one previously-leaked CC Menu token (a credential the token holder was never meant to use beyond its own stack). This matches "High — unauthenticated read of stack state" (the read is authenticated as *some* client, but the underlying access-control boundary of a stack-scoped token is bypassed for a stack the token owner has no right to see), and edges toward the Critical bucket ("payload for one repository ... reading another's stack") since the whole point of `stack_id`-scoped `ApiClient`s is per-tenant isolation, which is broken here.

### Likelihood Explanation
Preconditions: a stack-scoped `ApiClient` must exist with `stack_id` set (a supported, documented feature exposed in the API clients UI) and its CC Menu token/URL must leak (e.g., pasted into a public CI badge, forwarded email, public README, or observed in a public build server config) — a scenario the feature explicitly anticipates as the token embeds directly in URLs. No GitHub secrets, session, or `api_clients_secret` are needed by the attacker; they only need the previously-issued, valid token string and knowledge/guess of another stack's `owner/repo/environment` path (stack ids are often predictable/public, e.g., `org/repo/production`). This is a single unauthenticated HTTP GET, fully repeatable, low cost.

### Recommendation
In `Shipit::Api::CCMenuController`, restore stack-scoping by resolving `stack` through the same client-scoped query used in `BaseController` (i.e., use `stacks.from_param!(params[:stack_id])` instead of `Stack.from_param!(params[:stack_id])`), or explicitly assert `current_api_client.stack_id.nil? || current_api_client.stack_id == stack.id` before rendering.

### Proof of Concept
```ruby
# test/controllers/api/ccmenu_controller_test.rb (conceptual)
test "a stack-scoped token cannot fetch another stack's cc_menu.xml" do
  stack_a = shipit_stacks(:shipit)
  stack_b = shipit_stacks(:shipit2) # or any other fixture stack
  client = ApiClient.create!(creator: shipit_users(:walrus), name: 'scoped', stack_id: stack_a.id, permissions: ['read:stack'])

  # sanity: token is valid for its own stack
  get api_stack_ccmenu_path(stack_id: stack_a.to_param, token: client.authentication_token, format: :xml)
  assert_response :success

  # exploit: same token replayed against a different stack id
  get api_stack_ccmenu_path(stack_id: stack_b.to_param, token: client.authentication_token, format: :xml)

  # binding under test: stack.id == current_api_client.stack_id
  assert_not_equal stack_b.id, client.stack_id
  assert_response :not_found # currently fails: controller returns 200 with stack_b's XML
end
```

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

**File:** config/routes.rb (L27-28)
```ruby
    scope '/stacks/*stack_id', stack_id: stack_id_format, as: :stack do
      get '/ccmenu' => 'ccmenu#show', as: :ccmenu
```
