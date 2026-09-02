### Title
`CCMenuController#stack` uses unscoped `Stack.from_param!`, bypassing token's `stack_id` binding - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Api::CCMenuController` overrides the base controller's scoped `stack` helper with its own private `stack` method that calls `Stack.from_param!(params[:stack_id])` directly, instead of the base `stacks.from_param!(params[:stack_id])` which restricts lookup to `Stack.where(id: current_api_client.stack_id)` when the client is stack-scoped. This lets a token minted for one stack's `ApiClient` be used to read CCMenu status for any other stack, since `check_permissions!` only checks permission-name membership and never checks stack ownership.

### Finding Description
The intended binding is `token's ApiClient#stack_id == stack_id param resolved`. In `BaseController#stack`/`#stacks` this binding is enforced: `stacks` is scoped to `Stack.where(id: current_api_client.stack_id)` when `current_api_client.stack_id?` is true, and `stack` resolves via `stacks.from_param!(params[:stack_id])`, so a scoped client can never resolve a stack outside its own `stack_id`. `app/controllers/shipit/api/base_controller.rb:74-80`

However, `Api::CCMenuController` defines its own `stack` method that ignores this scoping entirely:
```ruby
def stack
  @stack ||= Stack.from_param!(params[:stack_id])
end
```
`app/controllers/shipit/api/ccmenu_controller.rb:29-31`

This resolves against the full `Stack` relation regardless of `current_api_client.stack_id`. The controller also overrides `authenticate_api_client` to pull the token from `params[:token]` rather than an `Authorization` header, so any stack-scoped `ApiClient#authentication_token` shared as part of a CCMenu URL (`app/controllers/shipit/ccmenu_url_controller.rb`) works as the query param `token`. `app/controllers/shipit/api/ccmenu_controller.rb:33-36`

`ApiClient.authenticate` only verifies the HMAC signature and loads the client by id — it performs no stack check: `find_by(id: message_verifier.verify(token).to_i)`. `app/models/shipit/api_client.rb:24-27`

`require_permission :read, :stack` triggers `check_permissions!(:read, :stack)`, which only checks that `"read:stack"` is in the client's `permissions` array — it has no knowledge of which stack is being requested: `app/models/shipit/api_client.rb:38-45`. So a client scoped to stack A with `read:stack` permission satisfies this check for a request naming stack B.

Attacker flow: attacker obtains (via legitimate sharing, not theft) a CCMenu URL such as `/api/stacks/A/ccmenu.xml?token=<A-scoped-token>`. They then request `/api/stacks/B/ccmenu.xml?token=<A-scoped-token>`. `authenticate_api_client` succeeds (signature valid, client A found), `require_permission!(:read, :stack)` passes (client A has `read:stack`), and `stack` resolves stack B via the unscoped `Stack.from_param!`, rendering stack B's CCMenu XML (latest deploy/rollback status) to the holder of a stack-A-only credential.

No existing guard catches this: `verify_signature`/webhook checks are irrelevant here; `ExplicitParameters` isn't used on this action; `force_github_authentication` doesn't apply to the API namespace; the `stacks` scope exists but is bypassed by the controller's local override; there is no model validation tying `Stack#from_param!` results to caller identity.

### Impact Explanation
Any holder of a stack-scoped CCMenu token (a URL that is commonly shared/embedded in CI dashboards, README badges, or CCTray clients, and is explicitly designed to be lower-privilege than a full API token) can read the deploy/task status of every other stack in the Shipit instance, not just the one they were authorized for. This is a cross-stack information leak (unauthorized read of stack task/deploy status) matching the High severity category "unauthenticated/unauthorized read of stack state, task streams or deploy output." It is fully repeatable against arbitrary stack ids by simply changing the URL path segment, and requires no interaction with the victim beyond having once been given a CCMenu URL for any stack.

### Likelihood Explanation
Preconditions are minimal: the attacker just needs one legitimately-shared CCMenu token/URL for any stack (a normal, low-sensitivity artifact intended for status dashboards) and knowledge/guess of another stack's identifier (`Stack.from_param!` typically resolves by repository owner/name or id, both discoverable). No Shipit secrets, sessions, or elevated roles are needed. This is low-cost and highly feasible — a single crafted HTTP GET.

### Recommendation
Remove the `Api::CCMenuController#stack` override (or reuse the base scoped implementation) so that resolution goes through `stacks.from_param!(params[:stack_id])`, ensuring a stack-scoped `ApiClient#stack_id` is enforced against `params[:stack_id]` before rendering. If `CCMenuController` needs its own `authenticate_api_client`, it should still populate `@current_api_client` such that inherited `stacks`/`stack` scoping applies unchanged.

### Proof of Concept
```ruby
# test/controllers/shipit/api/ccmenu_controller_test.rb
test "a token scoped to stack A cannot read stack B's ccmenu status" do
  stack_a = shipit_stacks(:shipit)
  stack_b = shipit_stacks(:cyclimse) # any other fixture stack

  client = Shipit::ApiClient.create!(
    creator: shipit_users(:walrus),
    name: "scoped-client",
    stack: stack_a,
    permissions: ['read:stack'],
  )

  # Binding under test: client.stack_id must equal the resolved stack's id
  assert_equal stack_a.id, client.stack_id
  refute_equal stack_a.id, stack_b.id

  # Permission check passes regardless of target stack
  assert client.check_permissions!(:read, :stack)

  get ccmenu_api_stack_path(stack_b), params: { token: client.authentication_token }, format: :xml

  # Vulnerability: request succeeds and serves stack B despite client being scoped to stack A
  assert_response :success
  assert_includes @response.body, stack_b.repository.full_name
end
```
This demonstrates the divergence: `client.stack_id == stack_a.id` while the served record is `stack_b`, i.e. `client.stack_id != stack.id`, contradicting the intended binding, with `check_permissions!` passing throughout.