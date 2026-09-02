### Title
`Api::BaseController#stacks` treats `ApiClient` with `stack_id == nil` as unscoped instead of scope-less, letting the CCMenu client read every stack - ([File: app/controllers/shipit/api/base_controller.rb])

### Summary
`Api::BaseController#stacks` and `#stack` (`app/controllers/shipit/api/base_controller.rb:74-80`) use `current_api_client.stack_id?` to decide whether to restrict the query to one stack. Since Rails' boolean attribute predicate returns `false` for `nil`, an `ApiClient` whose `stack_id` column is `nil` falls through to `Stack.all`, so any endpoint under `Api::BaseController` other than `Api::CCMenuController` (e.g. `Api::StacksController`, `Api::TasksController`) will resolve `stack` against the entire `Stack` table for such a client.

### Finding Description
The intended binding is: `current_api_client.stack_id? == false` should imply "this client is restricted to zero stacks" (since `CCMenuUrlController#client` mints the client without ever setting `stack:`). Instead the code implements: `current_api_client.stack_id? == false` implies "this client is unrestricted (all stacks)". These are not equivalent, and the actual behavior is the latter: [1](#0-0) 

`CCMenuUrlController#client` creates (or finds) a persistent `ApiClient` record with `permissions: %w[read:stack]` and **no `stack:` association at all**: [2](#0-1) 

That record's `stack_id` column is `nil`. Its `authentication_token` (`ApiClient#authentication_token`, `app/models/shipit/api_client.rb:34-36`) is a normal HMAC-signed client ID that `ApiClient.authenticate(token)` (`app/models/shipit/api_client.rb:23-27`) will validate identically whether presented via `Api::CCMenuController`'s `params[:token]` auth override or via standard HTTP Basic Auth in `Api::BaseController#authenticate_api_client` (`app/controllers/shipit/api/base_controller.rb:48-56`).

Exploit flow:
1. A logged-in Shipit user visits the CCMenu URL feature for stack A, which calls `CCMenuUrlController#client`, creating/finding an `ApiClient` named "CCMenu Client" with `permissions: ['read:stack']`, `stack_id: nil`, and returns `client.authentication_token` embedded in the returned CCMenu URL. (The URL is delivered to a party who is allowed to see stack A's CCMenu page, but the token itself carries no stack restriction.)
2. Anyone in possession of that token sends `GET/POST` requests using HTTP Basic Auth with that token to `Api::StacksController#index`/`#show` or `Api::TasksController` for **stack B** (any stack in the installation), setting `params[:stack_id]` (or `:id`) to stack B.
3. `#stacks` evaluates `current_api_client.stack_id?` → `false` (nil `stack_id`) → returns `Stack.all` instead of an empty relation.
4. `#stack` calls `stacks.from_param!(params[:stack_id])`, which succeeds for stack B because `Stack.all` includes it.
5. `require_permission :read, :stack` only checks the permission string, not stack identity, so `check_permissions!(:read, :stack)` passes since `permissions` includes `'read:stack'`.

No existing guard intervenes: `require_permission!`/`check_permissions!` (`app/models/shipit/api_client.rb:38-45`) is permission-string-only and unaware of stack scoping; `authenticate_api_client` only validates the token's HMAC signature, not scope; and there is no separate stack-membership check anywhere else in `Api::BaseController` or its subclasses.

### Impact Explanation
Any token whose `stack_id` is `nil` - which the engine itself mints for every CCMenu URL user via `CCMenuUrlController#client` - becomes a read-all-stacks credential for `Api::StacksController#index/show`, exposing repository/branch/environment/lock state, task/deploy history, and other stack metadata for every stack in the installation, not just the one the CCMenu link was generated for. This is a cross-tenant read exposure (a credential scoped to one stack in intent reads all stacks in practice), matching the "unauthenticated/under-scoped read of stack state" High-severity category. If any nil-`stack_id` client is ever granted `write:stack` or `deploy:stack` (e.g. via a generically-created `ApiClient` from `/api_clients` without a stack), the same divergence would let it mutate or deploy/rollback stacks it was never meant to touch, escalating to Critical.

### Likelihood Explanation
Preconditions are trivially met by ordinary engine usage: the CCMenu URL feature (`CCMenuUrlController`) unconditionally creates a stack-less `ApiClient`, so every user who has ever used "CCMenu URL" for any stack already holds a working `Basic`-auth token that is nil-scoped. No secrets, GitHub credentials, or elevated Shipit roles are required beyond possessing that one token. The request is a single authenticated (with the token) HTTP GET to a standard API route; the read is fully repeatable against arbitrary stacks.

### Recommendation
Change the binding in `Api::BaseController#stacks` so a `nil` `stack_id` means "no stacks" rather than "all stacks" for clients that are meant to be stack-scoped, e.g. distinguish "globally unrestricted" clients (like `UnlimitedApiClient`) from "created for one stack" clients explicitly, and make `CCMenuUrlController#client` always persist `stack:` on creation so `stack_id?` is true. Concretely: `stacks` should return `Stack.none` (or raise) when the client is intended to be stack-scoped but has no `stack_id`, and only return `Stack.all` for clients that are explicitly marked unrestricted (e.g. `UnlimitedApiClient` or an explicit `unrestricted?` flag), not merely by `stack_id` being nil.

### Proof of Concept
```ruby
# test/controllers/api/stacks_controller_test.rb (new test)
test "an ApiClient with nil stack_id (as minted by CCMenuUrlController) can read every stack" do
  stack_a = shipit_stacks(:shipit)
  stack_b = shipit_stacks(:shipit2) # a different stack the client was never scoped to

  scopeless_client = ApiClient.create!(
    creator: shipit_users(:walrus),
    name: 'CCMenu Client',
    stack_id: nil,
    permissions: %w[read:stack]
  )

  authorization = { 'Authorization' => "Basic #{Base64.strict_encode64(scopeless_client.authentication_token + ':')}" }
  get shipit.api_stack_url(stack_b.to_param), headers: authorization

  assert_response :ok
  # Binding under test:
  # current_api_client.stack_id?  == false   (nil stack_id)
  # expected: client restricted to stack_a only -> stack_b lookup should 404 / Stack.none
  # actual:   Stack.all is returned, so stack_b is resolved successfully
  assert_equal stack_b.id, JSON.parse(response.body)['id']
end
```
This demonstrates that `#stacks` returns `Stack.all` (proving `stack_b` is reachable) for a client whose intended scope, per `CCMenuUrlController#client`, is a single stack.

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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L15-18)
```ruby
    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```
