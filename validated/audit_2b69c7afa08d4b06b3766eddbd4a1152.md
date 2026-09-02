### Title
CCMenu token minted for one stack authorizes reads of any stack - (File: app/controllers/shipit/ccmenu_url_controller.rb, app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Shipit::CCMenuUrlController#client` creates/reuses an `ApiClient` with `permissions: %w[read:stack]` but never sets `stack:`, so every user's CCMenu client is stack-unrestricted (`stack_id` is `nil`). Independently, `Shipit::Api::CCMenuController` overrides `#stack` to query `Stack.from_param!` directly instead of the base class's scoped `stacks.from_param!`, so it never checks `current_api_client.stack_id` at all — meaning even a properly-scoped client's token would work against any stack.

### Finding Description
The intended binding is: `current_api_client.stack_id == stack.id` (or `nil` meaning "no restriction should be granted for a token issued from a single-stack action"). This binding is broken twice:

1. `CCMenuUrlController#client` (app/controllers/shipit/ccmenu_url_controller.rb:15-18) does:
```ruby
@client ||= ApiClient.create_with(permissions: %w[read:stack])
                     .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
```
It never passes `stack: stack`, so `ApiClient#stack_id` is `nil` (unrestricted) for every user, regardless of which stack's CCMenu URL was requested. Because `find_or_create_by!` keys only on `creator` + `name`, the *same* `ApiClient` row (and thus the same `authentication_token`, since `ApiClient#authentication_token` is `message_verifier.generate(id)` — app/models/shipit/api_client.rb:34-36) is reused/returned for every stack that user ever visits `cc_menu_url` for.

2. Even disregarding (1), `Shipit::Api::BaseController#stacks` (app/controllers/shipit/api/base_controller.rb:74-76) is supposed to enforce scoping:
```ruby
def stacks
  @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
end
```
But `Shipit::Api::CCMenuController#stack` (app/controllers/shipit/api/ccmenu_controller.rb:29-31) overrides this entirely:
```ruby
def stack
  @stack ||= Stack.from_param!(params[:stack_id])
end
```
This bypasses `stacks` and hits `Stack.from_param!` unscoped, so `current_api_client.stack_id` is never consulted by this controller. `require_permission :read, :stack` (line 6) only checks the `read:stack` permission string, not which stack it applies to.

Attack flow: an authenticated user visits `GET /stacks/:owner/:repoA/:env/cc_menu_url`, minting/retrieving a token for their "CCMenu Client" `ApiClient` (stack_id nil). They then call `GET /api/stacks/:ownerB/:repoB/:envB/cc_menu.xml?token=<token>`. `authenticate_api_client` (ccmenu_controller.rb:33-36) verifies the token and sets `@current_api_client`, `require_permission!` passes since `read:stack` is present, and `#stack` resolves stack B unscoped — the deploy/rollback status XML for stack B is returned to a user who was never authorized for stack B.

No existing guard prevents this: `require_permission` only checks the operation/scope string not the target record; `stacks`/`stack_id` scoping exists in the base controller but is dead code for this specific controller.

### Impact Explanation
An authenticated user with legitimate access to only one stack can read deploy/rollback status (`stack.deploys_and_rollbacks.last`, rendered via `shipit/ccmenu/project.xml`) for any other stack in the Shipit instance, across repositories/teams they have no authorization for. This is a cross-tenant unauthorized read of stack state, matching the "High - unauthenticated/unauthorized read of stack state" impact category. It is fully repeatable: the token is long-lived (no expiry logic visible in `ApiClient.authenticate`), works against any `stack_id` param, and requires no further interaction once minted.

### Likelihood Explanation
Low cost, high feasibility: any logged-in Shipit user can trigger `#fetch` once to obtain a valid, indefinitely-reusable CCMenu token, then swap the `stack_id` route param to any other stack slug. No GitHub secrets, no privileged role, and no special stack/repo configuration are required — only that the target stack exists and is reachable via the standard `/api/stacks/:owner/:repo/:env/cc_menu.xml` route.

### Recommendation
- In `CCMenuUrlController#client`, scope the `ApiClient` to the specific stack (e.g. `create_with(permissions: %w[read:stack], stack: stack).find_or_create_by!(creator: current_user, stack: stack, name: 'CCMenu Client')`), and stop keying `find_or_create_by!` only on creator+name across stacks.
- In `Shipit::Api::CCMenuController`, remove the `#stack` override and use the base controller's scoped `stacks.from_param!(params[:stack_id])` so `current_api_client.stack_id` restrictions are honored.

### Proof of Concept
```ruby
# test/controllers/ccmenu_url_controller_test.rb (conceptual additions)
test "ccmenu client is not scoped to the requested stack" do
  session[:user_id] = @user.id
  get :fetch, params: { stack_id: @stack_a.to_param }
  client = Shipit::ApiClient.find_by(creator: @user, name: 'CCMenu Client')
  assert_nil client.stack_id # binding broken: should equal @stack_a.id
end

# test/controllers/api/ccmenu_controller_test.rb (conceptual additions)
test "token minted for stack A authorizes reads of stack B" do
  client = Shipit::ApiClient.create!(creator: @user, name: 'CCMenu Client', permissions: %w[read:stack]) # stack_id nil
  token = client.authentication_token
  get :show, params: { stack_id: @stack_b.to_param, token: token }
  assert_response :ok # unauthorized cross-stack read succeeds
end
```