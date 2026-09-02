### Title
`CCMenuController#stack` bypasses per-token stack scoping by querying `Stack.from_param!` instead of `stacks.from_param!` - (File: `app/controllers/shipit/api/ccmenu_controller.rb`)

### Summary
`Shipit::Api::BaseController#stack` correctly scopes lookups through `stacks` (`Stack.where(id: current_api_client.stack_id)`), but `Shipit::Api::CCMenuController` overrides `stack` to call `Stack.from_param!(params[:stack_id])` against the unscoped `Stack` model. Any valid `ApiClient` token scoped to one stack can therefore read the CCMenu XML build-status feed of any other stack by simply changing the `stack_id` in the URL.

### Finding Description
The intended binding is: `stack ∈ stacks` where `stacks = Stack.where(id: current_api_client.stack_id)` for scoped clients, as implemented in `BaseController#stacks`/`#stack` (`app/controllers/shipit/api/base_controller.rb:74-80`). `CCMenuController` redefines `stack` at `app/controllers/shipit/api/ccmenu_controller.rb:29-31`:

```ruby
def stack
  @stack ||= Stack.from_param!(params[:stack_id])
end
```

This resolves against `Stack.all` instead of `stacks`, so the equality `stack ∈ current_api_client.stack_id`-scoped set no longer holds — `stack` can be any stack in the system regardless of the token's `stack_id`.

`require_permission :read, :stack` only invokes `ApiClient#check_permissions!` (`app/models/shipit/api_client.rb:38-45`), which checks the string `permissions` array (`read:stack` present or not) but never compares `current_api_client.stack_id` to the requested `params[:stack_id]`. Authentication itself is also overridden to accept the `token` query parameter directly (`app/controllers/shipit/api/ccmenu_controller.rb:33-36`), which is legitimate design intent (CCMenu clients pass tokens via query string), but combined with the unscoped `stack` lookup it means a token scoped to stack A fully authenticates and is then used to fetch data for stack B.

Attacker request: `GET /api/stacks/<stack-B-id-or-slug>/ccmenu.xml?token=<token-for-stack-A>` where the `ApiClient` for token A has `stack_id` set to stack A and `permissions: ['read:stack']`. `authenticate_api_client` succeeds (token is valid), `require_permission!(:read, :stack)` succeeds (permission present), and `stack` resolves stack B via the unscoped `Stack.from_param!`, rendering stack B's CCMenu XML (build status, last build label/time, activity, web URL) to the attacker.

None of the existing guards catch this: `verify_signature`/webhook logic is irrelevant here; `authenticate_api_client` only validates the token's cryptographic signature, not stack scope; `require_permission!` checks operation/scope strings, not the target record; the `stacks` scoping helper exists but is bypassed by the override.

### Impact Explanation
The attacker gains unauthorized read access to another stack's CCMenu XML feed, exposing its deploy/build status, timestamps, and web URL for arbitrary stacks not owned by their token — an unauthenticated-relative-to-target-stack read of stack state. This is repeatable for every stack in the system with a single valid token from any one stack, giving full cross-tenant enumeration of build/deploy status. This matches the High severity category: "unauthenticated read of stack state, task streams or deploy output."

### Likelihood Explanation
Preconditions are minimal and realistic: the attacker needs only one legitimately issued `ApiClient` token scoped to any single stack with `read:stack` permission (a normal, low-privilege token type routinely created for CI/CCMenu integrations). No GitHub secrets, session, or elevated role is required. The attacker simply changes the `stack_id` path segment; the request costs nothing and is fully repeatable against every stack in the installation.

### Recommendation
Change `CCMenuController#stack` to delegate to the scoped `stacks` collection, matching the base controller's behavior:
```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```
Remove the unscoped `Stack.from_param!` call entirely so CCMenu lookups always honor `current_api_client.stack_id` scoping.

### Proof of Concept
Minitest controller test (`test/controllers/api/ccmenu_controller_test.rb`):
```ruby
test "a token scoped to stack A cannot fetch stack B's ccmenu xml" do
  stack_a = shipit_stacks(:shipit)
  stack_b = Stack.create!(repository: Repository.new(owner: "foo", name: "bar"), branch: 'main')

  client_a = ApiClient.create!(
    creator: shipit_users(:walrus),
    name: 'scoped-to-a',
    stack: stack_a,
    permissions: ['read:stack']
  )

  request.headers['Authorization'] = 'bleh' # disable basic auth path
  get :show, params: { stack_id: stack_b.to_param, token: client_a.authentication_token }

  # Assert the binding: stack must be ∈ Stack.where(id: client_a.stack_id) i.e. only stack_a
  assert_response :not_found # EXPECTED after fix; currently returns :ok with stack_b's XML
end
```
Before the fix, this test observes `assert_response :ok` and `assert_payload 'name', stack_b.to_param`, proving `client_a` (scoped to `stack_a`) can read `stack_b`'s data — demonstrating the scoping bypass.