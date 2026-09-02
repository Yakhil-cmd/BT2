### Title
CCMenu Client API token is not scoped to the requesting stack, granting read access to every stack in the instance - ([File: app/controllers/shipit/ccmenu_url_controller.rb])

### Summary
`CCMenuUrlController#client` finds-or-creates a single `ApiClient` named `'CCMenu Client'` per `current_user` via `find_or_create_by!(creator: current_user, name: 'CCMenu Client')`, never setting `stack:`/`stack_id:`. Because `ApiClient#stack_id` stays `nil`, the resulting `authentication_token` is unscoped and, per `Shipit::Api::BaseController#stacks`, grants `read:stack` access to `Stack.all` rather than just the requested stack.

### Finding Description
Binding claimed: `ApiClient#stack_id` created when requesting a CCMenu URL for stack A must equal `A.id`, and must differ for stack B (`client_for_A.stack_id == A.id && client_for_A.stack_id != client_for_B.stack_id`).

Actual code:
- `app/controllers/shipit/ccmenu_url_controller.rb:15-18`:
```ruby
def client
  @client ||= ApiClient.create_with(permissions: %w[read:stack])
                       .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
end
```
This lookup/creation key is only `{creator, name: 'CCMenu Client'}` — `stack` is never part of the `find_or_create_by!` key nor part of `create_with`, so `stack_id` defaults to `nil` (it's `optional: true` on the `belongs_to :stack` in `app/models/shipit/api_client.rb:8`).

- Once a user requests a CCMenu URL for any stack, one `ApiClient` row is created for that user with `stack_id: nil`. Any subsequent call to `#fetch` for a *different* stack by the same `current_user` finds the same row (same creator + same fixed name) and mints a token for the **same** `ApiClient` id — because `authentication_token` is `message_verifier.generate(id)` (`app/models/shipit/api_client.rb:34-36`), it's the identical token every time for that user.

- That token's authorization scope is determined server-side in `app/controllers/shipit/api/base_controller.rb:74-76`:
```ruby
def stacks
  @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
end
```
With `stack_id` nil, `stacks` resolves to `Stack.all` — global read access, not scoped to any one stack. Worse, `Shipit::Api::CCMenuController` (`app/controllers/shipit/api/ccmenu_controller.rb:29-31`) overrides `stack` to call `Stack.from_param!(params[:stack_id])` directly, bypassing the `stacks` scoping method entirely, so even a properly stack-scoped `ApiClient` token would still work against any `stack_id` in the URL for the CCMenu endpoint specifically. The only server-side check performed is `require_permission :read, :stack`, i.e. `current_api_client.check_permissions!('read', 'stack')` (`app/controllers/shipit/api/base_controller.rb:82-84`), which validates the *permission name*, not the *stack scope*.

Existing guards checked and found insufficient:
- `require_permission!`/`check_permissions!` only checks the `permissions` array (`read:stack` present), never `stack_id`.
- The `stacks` scoping helper is bypassed by `CCMenuController#stack`.
- No validation on `ApiClient` enforces stack-uniqueness or requires `stack_id` presence.

Attacker path: attacker is the same authenticated Shipit user (not an unprivileged external attacker, but the finding is about the token itself becoming an over-broad credential once minted and handed out). The URL that an operator publishes/embeds in a public build-radiator display for stack A (`.../ccmenu.xml?token=<token>`) contains a token which — because `stack_id` is nil — is valid for `GET /api/1/stacks/:any_stack_id/ccmenu.xml?token=<token>` for **every** stack in the instance, not just stack A. Anyone who obtains that one URL (which is explicitly designed to be posted publicly, e.g. on a CI radiator/dashboard) can enumerate and read build status (`lastBuildStatus`, `lastBuildLabel`, lock state, activity) for all other stacks.

### Impact Explanation
An unauthenticated holder of one CCMenu URL (intended for a single, possibly public radiator display) gains unauthenticated read access to build/deploy status and lock state of every stack in the Shipit instance via `Shipit::Api::CCMenuController#show`. This matches the "unauthenticated read of stack state" High-severity category. It does not grant write/deploy/rollback capability (permission is only `read:stack`), and does not leak GitHub tokens or secrets, so it stays at High rather than Critical. It is fully repeatable: the same leaked token works against arbitrary `stack_id` values indefinitely, across all stacks, since the `ApiClient` row is permanently unscoped once created.

### Likelihood Explanation
Preconditions: a Shipit operator must have used the "CCMenu URL" feature (`CCMenuUrlController#fetch`) for at least one stack, and the resulting URL/token must reach someone outside the trust boundary — a scenario the feature explicitly encourages (posting the URL on a public build radiator). No GitHub secrets, session, or privileged role is required by the person exploiting the leaked token; they only need the token string and the target `stack_id` (stack slugs are typically guessable/enumerable, e.g. `owner/repo/branch`). This makes exploitation low-cost and highly feasible once a single CCMenu URL has been disclosed.

### Recommendation
Scope the `ApiClient` per (creator, stack) instead of per creator only, and enforce that the CCMenu API path uses the stack-scoped lookup:
- In `CCMenuUrlController#client`, include `stack: stack` (or `stack_id: stack.id`) in both `create_with` and `find_or_create_by!`, and use a name that doesn't collide across stacks (or rely on the stack in the lookup key), e.g.:
```ruby
def client
  @client ||= ApiClient.create_with(permissions: %w[read:stack])
                       .find_or_create_by!(creator: current_user, stack: stack, name: 'CCMenu Client')
end
```
- In `Shipit::Api::CCMenuController`, remove the direct `Stack.from_param!` override and use the inherited, scoped `stacks.from_param!(params[:stack_id])` from `BaseController`, so a stack-scoped token cannot be replayed against other stacks.

### Proof of Concept
```ruby
# test/controllers/ccmenu_controller_test.rb
test ":fetch scopes the ApiClient to the requested stack" do
  other_stack = shipit_stacks(:cyclimse) # a different fixture stack

  get :fetch, params: { stack_id: @stack.to_param }
  client_a = ApiClient.last

  get :fetch, params: { stack_id: other_stack.to_param }
  client_b = ApiClient.last

  assert_equal @stack.id, client_a.stack_id, "token for stack A must be scoped to stack A"
  assert_equal other_stack.id, client_b.stack_id, "token for stack B must be scoped to stack B"
  refute_equal client_a.id, client_b.id, "each stack must get its own ApiClient/token"
end
```
Currently this fails: both requests return the *same* `ApiClient.last` row with `stack_id == nil`, demonstrating the token is shared and unscoped across stacks.