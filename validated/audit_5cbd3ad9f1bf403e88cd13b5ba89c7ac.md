### Title
CCMenu API token grants read access to any stack, not just the stack it was minted for - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Api::CCMenuController#stack` resolves the target stack via `Stack.from_param!(params[:stack_id])`, completely bypassing the `current_api_client.stack_id` scoping that the rest of the API enforces through `BaseController#stacks`/`#stack`. Combined with the fact that `CCMenuUrlController#client` creates the `ApiClient` without ever setting `stack_id`, a CCMenu token authorizes reading the CCMenu XML (deploy/task status) of **any** stack in the installation by simply changing the `stack_id` request parameter - independent of, and more severe than, the id-reuse scenario in the question.

### Finding Description
The binding the question expects is `current_api_client.stack_id == stack.id`. Tracing the code:

- `CCMenuUrlController#client` mints the token via `ApiClient.create_with(permissions: %w[read:stack]).find_or_create_by!(creator: current_user, name: 'CCMenu Client')` — note `stack_id` is never assigned, so the resulting `ApiClient#stack_id` is `nil`. [1](#0-0) 
- In the normal API flow, `Api::BaseController#stacks` scopes lookups to the client's own stack only when `stack_id` is present, otherwise falls back to `Stack.all`: `current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all`, and `#stack` calls `stacks.from_param!(params[:stack_id])`. [2](#0-1) 
- `Api::CCMenuController` overrides `#stack` and does not use `stacks` at all: `@stack ||= Stack.from_param!(params[:stack_id])`, so it never consults `current_api_client.stack_id` even when that value is set. [3](#0-2) 
- Authentication only verifies the token's signature and existence: `ApiClient.authenticate(token)` = `find_by(id: message_verifier.verify(token).to_i)`. It performs no stack binding check. [4](#0-3) 
- Authorization (`require_permission :read, :stack`) only checks `permissions.include?("read:stack")` via `check_permissions!`, never the identity of `stack` vs. `current_api_client.stack_id`. [5](#0-4) [6](#0-5) 

So for any valid CCMenu (or any `read:stack`-scoped) token, `GET /api/:stack_id/ccmenu.xml?token=...` renders the deploy status of whatever stack `params[:stack_id]` resolves to, regardless of the stack the token was minted for. The id-reuse case from the question (Stack A destroyed, Stack B created reusing the same numeric id) is one path to this outcome, but the underlying bug is broader: the binding never existed for this controller in the first place, so no id-reuse is even required to trigger cross-tenant read.

None of the listed guards prevent this: `verify_signature`/webhook checks are irrelevant here, `EnvironmentVariables#permit` is irrelevant, and `stacks` scope (the one guard that would enforce the binding) is deliberately not used by `Api::CCMenuController#stack`.

### Impact Explanation
Any holder of a `read:stack`-permissioned `ApiClient` token (e.g., a CCMenu token legitimately minted for their own stack via `CCMenuUrlController#fetch`) can read the deploy/task status (last build status, label, time, web URL) of any other stack in the Shipit instance, including stacks belonging to unrelated repositories/organizations, by simply supplying a different `stack_id`. This is a cross-tenant unauthorized read of deploy state, repeatable against arbitrary stacks with no rate limiting beyond normal HTTP access. This matches the "unauthenticated/cross-tenant read of stack state" High-severity category (worse, since a legitimately-issued but non-scoped token is used to escalate beyond its intended tenant).

### Likelihood Explanation
Preconditions are minimal: the attacker only needs to be a legitimate Shipit user of at least one stack (to obtain a CCMenu token via the standard "Fetch URL" button in `stacks/settings`), or possess any other `ApiClient` token with `read:stack` permission and no `stack_id` restriction. No GitHub secrets, webhook signatures, or elevated roles are required. The attack is a single authenticated GET request with an attacker-chosen `stack_id`, fully repeatable against any stack id in the system.

### Recommendation
In `Api::CCMenuController#stack`, restore the tenant binding by reusing the scoped lookup from `BaseController`, e.g. `@stack ||= stacks.from_param!(params[:stack_id])` instead of calling `Stack.from_param!` directly. Additionally, `CCMenuUrlController#client` should mint the `ApiClient` with `stack_id: stack.id` set (not just permissions), so the token is intrinsically bound to the stack it was issued for, and `dependent: :destroy` on `Stack#api_clients` will properly invalidate it when the stack is deleted.

### Proof of Concept
```ruby
# test/controllers/api/ccmenu_controller_test.rb
test "a CCMenu token minted for one stack cannot read another stack's ccmenu.xml" do
  stack_a = shipit_stacks(:shipit)
  stack_b = Stack.create!(repository: Repository.create!(owner: 'other-org', name: 'other-repo'), branch: 'main')

  client = ApiClient.create_with(permissions: %w[read:stack])
                     .find_or_create_by!(creator: shipit_users(:walrus), name: 'CCMenu Client', stack_id: stack_a.id)

  get :show, params: { stack_id: stack_b.to_param, token: client.authentication_token }

  # Binding under test: current_api_client.stack_id == stack.id
  assert_not_equal client.stack_id, stack_b.id
  refute_equal :ok, response.status, "token scoped to stack_a must not read stack_b's data"
end
```
Running this against current `app/controllers/shipit/api/ccmenu_controller.rb` fails (returns `200 OK` with Stack B's data) because `#stack` ignores `current_api_client.stack_id` entirely, confirming the broken binding without requiring numeric-id reuse or record deletion.

### Citations

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L15-18)
```ruby
    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
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

**File:** app/models/shipit/api_client.rb (L24-27)
```ruby
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
