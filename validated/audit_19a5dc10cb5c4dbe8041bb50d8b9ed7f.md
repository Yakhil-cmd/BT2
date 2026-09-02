### Title
API-scoped `ApiClient` tokens can read CCMenu status for any stack, bypassing per-token stack scoping - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Shipit::Api::CCMenuController` overrides the base controller's `stack` lookup method in a way that skips the per-`ApiClient` stack-scoping check that every other API controller relies on, letting a token that is scoped to one stack read CCMenu deploy/build status for any other stack in the installation.

### Finding Description
Every other API controller resolves the target stack through `Shipit::Api::BaseController#stack`, which is deliberately scoped to the current token: [1](#0-0) 
```ruby
def stacks
  @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
end

def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```
This ensures that when an `ApiClient` record has a `stack_id` set (`belongs_to :stack, optional: true`), that token can only resolve stacks matching its own `stack_id` — i.e., the "stack a token authorizes" and "the stack it touches" are the same record.

`CCMenuController`, however, defines its own `stack` private method that bypasses this scoping entirely, calling `Stack.from_param!` directly on the unscoped `Stack` model:
```ruby
def stack
  @stack ||= Stack.from_param!(params[:stack_id])
end
``` [2](#0-1) 

Authentication for this controller is also customized to accept a bare `token` query parameter (used by CI dashboard tools):
```ruby
def authenticate_api_client
  @current_api_client = ApiClient.authenticate(params[:token])
  super unless @current_api_client
end
``` [3](#0-2) 

The only authorization check applied is a coarse-grained permission check unrelated to which stack is targeted: [4](#0-3) 
```ruby
require_permission :read, :stack
```
`require_permission!` only verifies `permissions.include?("read:stack")` via `ApiClient#check_permissions!`, it never verifies which `stack_id` the token belongs to: [5](#0-4) 

Because `#stack` in `CCMenuController` resolves the target stack from the unscoped `Stack` relation instead of `current_api_client`-scoped `stacks`, an `ApiClient` whose `stack_id` binds it to Stack A can supply an arbitrary `stack_id` for the CCMenu endpoint and read deploy state for Stack B, C, etc. — any stack the requester chooses. This breaks the equality that should hold: `token.stack_id == stack_touched.id`.

### Impact Explanation
This is an authorization-scope escalation: a credential explicitly restricted to one stack (`ApiClient#stack_id`) can be used to read deploy/build state (`latest_deploy`, running status, last build label/status/time) of any other stack in the Shipit instance. This matches the High-severity class "unauthenticated read of stack state ... " because it grants read access to stack state outside the credential's authorized scope, without any additional authentication check tying the token to the requested stack.

### Likelihood Explanation
Any holder of a stack-scoped `ApiClient` token (e.g., a CI system or third-party integration granted `read:stack` for a single stack) can trivially exploit this by making a GET request to the CCMenu endpoint with a different `stack_id` in the URL/path and their own valid token — no privilege escalation trick beyond parameter substitution is required.

### Recommendation
Have `CCMenuController#stack` reuse the scoped `stacks` lookup from `BaseController` (i.e., `stacks.from_param!(params[:stack_id])`) instead of calling `Stack.from_param!` on the unscoped `Stack` model, so that stack-scoped `ApiClient` tokens cannot resolve stacks outside their `stack_id`.

### Proof of Concept
1. Create/obtain an `ApiClient` with `stack_id` set to Stack A and permission `read:stack` (e.g. via the CCMenu URL flow or admin UI).
2. Send `GET /api/<stack-B-owner>/<stack-B-repo>/<stack-B-env>/ccmenu.xml?token=<stackA_token>` (path shape per `config/routes.rb` API scoping for `ccmenu`), substituting Stack B's identifiers instead of Stack A's.
3. Because `CCMenuController#stack` calls `Stack.from_param!(params[:stack_id])` without checking `current_api_client.stack_id`, the request succeeds and returns Stack B's CCMenu XML (build status, last deploy time, etc.), even though the token is only authorized for Stack A.

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L5-6)
```ruby
    class CCMenuController < BaseController
      require_permission :read, :stack
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L27-31)
```ruby
      private

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
