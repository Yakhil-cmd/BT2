### Title
CCMenu API token not scoped to its issuing stack, allowing cross-stack build-status disclosure - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Shipit::Api::BaseController#stack` correctly restricts stack lookups to `current_api_client.stack_id` via the `stacks` scoping method, but `Shipit::Api::CCMenuController` overrides `stack` to call `Stack.from_param!(params[:stack_id])` directly, bypassing that scope entirely. Any valid CCMenu API token (minted per-stack by `CCMenuUrlController#fetch`) can therefore be replayed against `GET /stacks/:stack_id/ccmenu?token=...` for any other stack to read its build status.

### Finding Description
The intended binding is: `params[:stack_id]` resolved by the controller must satisfy `current_api_client.stack_id.nil? || stack.id == current_api_client.stack_id`. This is exactly what the base implementation enforces: [1](#0-0) 

However, `CCMenuController` redefines `stack` and completely ignores `current_api_client.stack_id`: [2](#0-1) 

`require_permission :read, :stack` only checks that the token carries the `read:stack` permission string, not which stack it is bound to: [3](#0-2) 

`CCMenuUrlController#fetch` mints such a token via `find_or_create_by!(creator: current_user, name: 'CCMenu Client')`, which does not pass `stack:`, so the created `ApiClient` has `stack_id` nil by default: [4](#0-3) 

Because `ApiClient#authenticate` only verifies the signature and looks the record up by id — it does not consult `stack_id` at all — and `CCMenuController#stack` never reads `current_api_client.stack_id`, **any** valid ccmenu token (whether its `stack_id` is nil or set to a specific stack) can be used to fetch the CCMenu XML for an arbitrary stack by simply changing `params[:stack_id]` in the URL. The exploit is:
1. Attacker views a stack-A settings page they're authorized to see and clicks "Fetch URL," obtaining a URL like `/stacks/:stack_id/ccmenu?token=<T>`.
2. Attacker requests `GET /stacks/<stack_id_B>/ccmenu?token=<T>` for an arbitrary stack B they have no access to.
3. `CCMenuController#show` renders stack B's latest deploy/rollback status using the token that was only ever meant for stack A.

No existing guard prevents this: `authenticate_api_client` only checks the signature is valid, `require_permission!` only checks the permission string, and the base controller's stack-scoping logic (`stacks`) is dead code from `CCMenuController`'s point of view because it is shadowed.

### Impact Explanation
This is an authorization/scope-bypass allowing cross-tenant read of build status and labels (deploy/rollback state, timestamps) for any stack, using any previously issued CCMenu token — including tokens minted for a completely unrelated stack. This matches the "unauthenticated/unauthorized read of stack state" High-severity category: the token is valid but not bound to the resource it's used against, so an attacker with a token for stack A gains persistent, repeatable read access to any other stack's CI/CD status by simply changing the URL path parameter.

### Likelihood Explanation
The attacker only needs to have legitimately obtained one ccmenu URL/token for any stack they can view (a low bar — clicking "Fetch URL" on a stack's settings page they have read access to). No secrets, no privileged role, and no live GitHub interaction are required; the exploit is a single crafted HTTP GET with the same query parameter swapped for a different `stack_id`. This is trivially repeatable against any number of stacks.

### Recommendation
Remove the `stack` override in `Shipit::Api::CCMenuController` (or make it enforce scoping) so it uses the same scoped lookup as the base controller, e.g.:
```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```
so that `current_api_client.stack_id` is honored. Additionally, consider having `CCMenuUrlController#client` explicitly set `stack:` on the created `ApiClient` so tokens are hard-bound to the stack they were generated for, rather than defaulting to an unscoped (`stack_id: nil`) client.

### Proof of Concept
```ruby
# test/controllers/api/ccmenu_controller_test.rb
module Shipit
  module Api
    class CCMenuControllerTest < ActionController::TestCase
      test "a token issued for stack A cannot read stack B" do
        stack_a = shipit_stacks(:shipit)
        stack_b = Stack.create!(repository: Repository.create!(owner: 'other', name: 'repo'), environment: 'production')

        client = ApiClient.create!(creator: shipit_users(:walrus), name: 'CCMenu Client A', permissions: %w[read:stack], stack: stack_a)
        token = client.authentication_token

        get :show, params: { stack_id: stack_b.to_param, token: token }

        # Binding under test: stack.id == current_api_client.stack_id
        assert_not_equal stack_a.id, stack_b.id
        assert_response :ok # FAILS the security expectation: should be :forbidden/:not_found since client.stack_id (stack_a.id) != stack_b.id
        assert_includes response.body, stack_b.repository.full_name
      end
    end
  end
end
```
This demonstrates that `CCMenuController#stack`'s bypass of `current_api_client.stack_id` scoping allows a token minted for stack A to successfully retrieve stack B's CCMenu data (`:ok` instead of the expected rejection).

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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L15-18)
```ruby
    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```
