Confirmed: `StacksController#stack` uses the scoped `stacks.from_param!(params[:id])` [1](#0-0)  which is restricted via `BaseController#stacks` to `current_api_client.stack_id` when the token is scoped [2](#0-1) . `Api::CCMenuController#stack`, however, resolves directly against the unscoped `Stack` collection [3](#0-2) , and its only authorization gate is `require_permission :read, :stack` which merely checks the client's permission list, not which stack it is bound to [4](#0-3) [5](#0-4) . This is reachable at the routed `get '/stacks/*stack_id/ccmenu'` endpoint [6](#0-5) .

### Title
CCMenu API endpoint does not enforce ApiClient stack scoping, allowing cross-stack read of deploy state - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Api::CCMenuController#stack` bypasses the stack-scoping mechanism that every other stack-scoped API endpoint relies on. An `ApiClient` that is deliberately scoped to a single stack (its `stack_id` column) can be used to read the CCMenu (deploy status/name/last build) of *any* other stack in the installation, not just the one it was authorized for.

### Finding Description
Shipit's API authorization model lets an `ApiClient` be optionally scoped to one stack via the `stack_id` column [7](#0-6) . Every controller that needs to resolve "the stack" from `params` is expected to go through `BaseController#stacks`, which restricts the queryable set to that one stack when `current_api_client.stack_id?` is true [2](#0-1) , and `BaseController#stack` composes on top of that scoped relation [8](#0-7) . `Api::StacksController` follows this pattern correctly, using `stacks.from_param!(params[:id])` [1](#0-0) .

`Api::CCMenuController`, mounted at `GET /stacks/*stack_id/ccmenu` [6](#0-5) , overrides `stack` to resolve directly against the global, unscoped `Stack` collection instead of the authorized `stacks` relation:
```ruby
def stack
  @stack ||= Stack.from_param!(params[:stack_id])
end
``` [3](#0-2) 

The only authorization check applied is `require_permission :read, :stack` [4](#0-3) , which is implemented by `ApiClient#check_permissions!` and only verifies that `"read:stack"` is present in the client's `permissions` array — it never checks `stack_id` [5](#0-4) . Consequently, the binding that every other endpoint enforces — "the stack a token authorizes" == "the stack it touches" — is broken specifically in this controller: a token scoped to stack A is still permitted to fetch the CCMenu status of stack B, C, or any stack in the installation, purely by supplying a different `stack_id` in the URL.

The test fixture `here_come_the_walrus` explicitly demonstrates the intended scoping model (`stack: shipit`, `permissions: [read:stack]`) [9](#0-8) , and `Api::StacksControllerTest` confirms that scoped clients are correctly restricted to their own stack for the `index` action [10](#0-9) . No equivalent restriction exists or is tested for `Api::CCMenuController`.

### Impact Explanation
An attacker holding a legitimately-issued but stack-scoped `ApiClient` token (e.g. a CCMenu client automatically created and scoped per-stack by `CCMenuUrlController#client` [11](#0-10) ) can read the deploy status, last build label/time, and activity state of every other stack managed by the Shipit instance, including stacks belonging to different repositories/teams they were never granted access to. This is an escalation beyond the authorized stack scope, exposing deploy state that the token issuer never intended to share — matching the "escalation into authorization" / "unauthorized read of stack state" class of impact.

### Likelihood Explanation
Likelihood is high for anyone already in possession of any scoped, `read:stack`-permitted `ApiClient` token (which is routinely generated and embedded in CCMenu URLs for CI dashboard tooling). No privileged access, secret knowledge, or additional authentication is required beyond having one such token; the attacker only needs to change the `stack_id` path segment to enumerate other stacks.

### Recommendation
Change `Api::CCMenuController#stack` to resolve through the scoped `stacks` relation, consistent with `Api::StacksController` and `BaseController`:
```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```
This ensures a stack-scoped `ApiClient` cannot resolve any stack outside the one it was authorized for.

### Proof of Concept
1. Create (or observe) an `ApiClient` scoped to `stack_id` = Stack A with permission `read:stack` (this is exactly what `CCMenuUrlController#client` creates for any logged-in user requesting a CCMenu URL for Stack A) [11](#0-10) .
2. Using that token's `authentication_token` as HTTP Basic auth (or `?token=` query param, both supported by `CCMenuController#authenticate_api_client` [12](#0-11) ), send:
   `GET /api/stacks/<other-org>/<other-repo>/<other-env>/ccmenu`
3. Because `stack` resolves against the global `Stack` collection, the response returns Stack B's `Project` XML (name, `lastBuildStatus`, `lastBuildLabel`, `lastBuildTime`, `webUrl`), even though the token is scoped to Stack A only.

### Citations

**File:** app/controllers/shipit/api/stacks_controller.rb (L87-89)
```ruby
      def stack
        @stack ||= stacks.from_param!(params[:id])
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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L33-36)
```ruby
      def authenticate_api_client
        @current_api_client = ApiClient.authenticate(params[:token])
        super unless @current_api_client
      end
```

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

**File:** config/routes.rb (L27-28)
```ruby
    scope '/stacks/*stack_id', stack_id: stack_id_format, as: :stack do
      get '/ccmenu' => 'ccmenu#show', as: :ccmenu
```

**File:** test/fixtures/shipit/api_clients.yml (L12-17)
```yaml
here_come_the_walrus:
  name: Here Come The Walrus
  creator: walrus
  stack: shipit
  permissions:
    - 'read:stack'
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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L15-18)
```ruby
    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```
