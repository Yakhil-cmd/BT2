## Finding

### Title
Stack-scoped `ApiClient` token bypasses stack authorization scope in CCMenu endpoint - (File: `app/controllers/shipit/api/ccmenu_controller.rb`)

### Summary
`Shipit::Api::BaseController` binds an `ApiClient` token to a specific `Stack` when the token is scoped (`stack_id?`), and every controller is expected to resolve the current stack through the scoped `stacks` relation. `Shipit::Api::CCMenuController` overrides `#stack` to bypass that scoping, resolving the stack directly from the URL parameter against the entire `Stack` table, breaking the binding between "the stack a token authorizes" and "the stack the controller action touches."

### Finding Description
`BaseController` defines the trust boundary for stack-scoped API tokens: [1](#0-0) 

`stacks` restricts the queryable set to `current_api_client.stack_id` when the client is scoped, and `stack` (used by every other API controller such as `DeploysController`, `CommitsController`, `StacksController`) resolves the requested stack from that restricted relation via `stacks.from_param!(params[:stack_id])`.

`CCMenuController`, however, defines its own `#stack` that ignores this scoping entirely: [2](#0-1) 

It calls `Stack.from_param!(params[:stack_id])` directly against the unscoped `Stack` model instead of the memoized `stacks` relation from `BaseController`. `require_permission :read, :stack` only checks that the token carries the string permission `read:stack` via `ApiClient#check_permissions!`: [3](#0-2) 

`check_permissions!` has no notion of which stack the operation targets — the actual stack-scoping check exists only in `BaseController#stacks`/`#stack`, which `CCMenuController` does not use.

The equality that should hold, and is broken, is:

`stack the ApiClient's stack_id authorizes` == `stack the CCMenuController#show action touches`

Before the request: a token created with a `stack_id` (e.g. fixture `here_come_the_walrus`) is meant to see only that one stack, as enforced and tested elsewhere (`test/controllers/api/stacks_controller_test.rb`: "an api client scoped to a stack will only see that one stack"). After the request to `Api::CCMenuController#show` with an arbitrary `stack_id` param, the token — which only needs the generic `read:stack` permission, not authorization for that particular stack — receives the CCTray/CCMenu XML status (`name`, `activity`, `lastBuildStatus`, `lastBuildLabel`, `lastBuildTime`, `webUrl`) of any stack in the installation, not just the one it was scoped to.

### Impact Explanation
This is an authorization-scope escalation: a token intentionally restricted to one stack (e.g. issued to a third-party CI/monitoring integration) can read build/deploy status and metadata of any other stack managed by the Shipit instance by requesting `/ccmenu/:stack_id`, only requiring possession of a valid but narrowly-scoped `read:stack` token. This matches the "unauthenticated read of stack state" (relative to the specific stack) category, since the request is not authorized for that stack even though it is authenticated for a different one.

### Likelihood Explanation
Exploitation requires only a valid `ApiClient` token that has `read:stack` permission and is scoped to any stack (a normal, lower-privilege token configuration many installations use for third-party integrations). No signature, GitHub credential, or admin privilege is required to enumerate `stack_id` values for other stacks in the same Shipit deployment — `Stack.from_param!` accepts the routable `stack_id` used throughout the app (org/repo/env path).

### Recommendation
Change `CCMenuController#stack` to use the inherited, scope-respecting `stacks` relation instead of querying `Stack` directly:
```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```
This ensures `current_api_client.stack_id` restrictions defined in `BaseController#stacks` are enforced for the CCMenu endpoint exactly as they are for every other API controller.

### Proof of Concept
1. Create an `ApiClient` scoped to `stack_id: A` with permission `read:stack` (as in fixture `here_come_the_walrus`).
2. Using that client's `authentication_token`, request `GET /ccmenu/<owner_b>/<repo_b>/<env_b>?token=<token>` for a different stack `B` that the client is not scoped to.
3. Observe the response returns `200 OK` with stack `B`'s CCTray XML (`name`, `lastBuildStatus`, etc.), even though `stacks_controller_test.rb` confirms the same token is restricted to stack `A` when accessed via `Api::StacksController#index`. [4](#0-3)

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L27-36)
```ruby
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
