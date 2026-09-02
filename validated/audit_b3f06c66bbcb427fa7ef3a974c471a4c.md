### Title
CCMenuController#show bypasses per-stack scoping, allowing a stack-scoped API token to read any stack's deploy status - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`CCMenuController#stack` resolves the target stack via `Stack.from_param!(params[:stack_id])` instead of the scope-aware `stacks.from_param!` helper used by every other API controller. Because `require_permission :read, :stack` only checks that the token has the literal `read:stack` permission string and never checks `current_api_client.stack_id`, any token with `read:stack` (even one explicitly scoped to a single stack) can fetch the CCMenu XML for every other stack in the instance by iterating `stack_id` path segments.

### Finding Description
The broken binding: for a scoped token, `current_api_client.stack_id == stack.id` must hold before rendering; in `CCMenuController#show` this is never checked (equality is never evaluated at all).

Code path:
- `app/controllers/shipit/api/base_controller.rb` defines the safe pattern: `stacks` returns `Stack.where(id: current_api_client.stack_id)` when the client is scoped, `Stack.all` otherwise, and `stack` calls `stacks.from_param!(params[:stack_id])`. [1](#0-0) 
- `CCMenuController` overrides `stack` and drops the `stacks` scoping entirely, querying `Stack.from_param!(params[:stack_id])` against **all** stacks regardless of `current_api_client.stack_id`: [2](#0-1) 
- `require_permission :read, :stack` only calls `current_api_client.check_permissions!(operation, scope)`, which checks membership in the `permissions` array, not the `stack_id` scope: [3](#0-2) 
- The custom `authenticate_api_client` in `CCMenuController` also accepts a token via the `token` query-string param (for CCMenu clients), but only authenticates the credential, again with no scope check: [4](#0-3) 

The test fixture `here_come_the_walrus` demonstrates the intended scoping model: a client with `stack: shipit`, `permissions: ['read:stack']`, whose index results are supposed to be restricted to that one stack (`test/controllers/api/stacks_controller_test.rb:217-223`), confirming other controllers correctly consult `current_api_client.stack_id`. `CCMenuController` is the exception where this check is missing.

Attacker flow: obtain (or be issued) an API-client token scoped to stack A with `read:stack` permission (e.g., via the legitimate CCMenu URL flow at `ccmenu_url#fetch`, which mints exactly such a read-only, stack-scoped token per `test/controllers/ccmenu_controller_test.rb:21-25`). Using that single token, issue `GET /api/stacks/:owner/:repo/:branch/ccmenu?token=<token>` for arbitrary `owner/repo/branch` combinations. Because `stack` is resolved unscoped, any existing stack B returns 200 with its latest deploy/rollback status, branch, activity and build label in the XML body; a nonexistent stack returns 404, letting the attacker enumerate which repositories/branches are configured as Shipit stacks.

### Impact Explanation
This is an unauthenticated-relative-to-scope read of stack state: a credential intentionally restricted to one stack discloses build/deploy status (`lastBuildStatus`, `lastBuildLabel`, `activity`, `webUrl`) and existence of every other stack on the instance. No secrets, PTY execution, or write access is obtained, but it is a cross-tenant information disclosure at scale — matching the High category "unauthorized read of stack state" from the impact list. It does not escalate to write/deploy actions, so it is not Critical.

### Likelihood Explanation
Preconditions are low: the attacker only needs one legitimately-issued, narrowly-scoped `read:stack` token (these are routinely handed out via the CCMenu URL feature intended for read-only monitoring integrations) and the ability to send GET requests with varying `stack_id` path segments — no GitHub credentials, sessions, or Shipit secrets required. This is trivially repeatable and scriptable against every `owner/repo/branch` guess.

### Recommendation
Change `CCMenuController#stack` to reuse the scope-aware helper instead of querying `Stack` directly, e.g. delegate to `stacks.from_param!(params[:stack_id])` (inheriting `BaseController#stacks`, which already restricts to `current_api_client.stack_id` when the client is scoped), removing the private override that queries `Stack.from_param!` unscoped.

### Proof of Concept
```ruby
# test/controllers/api/ccmenu_controller_test.rb
test "a stack-scoped token cannot read other stacks via ccmenu" do
  scoped_client = shipit_api_clients(:here_come_the_walrus) # stack: shipit, permissions: [read:stack]
  other_stack = Stack.create!(repository: Repository.new(owner: "foo", name: "bar"), branch: 'main')

  # Binding under test: scoped_client.stack_id == requested stack.id
  assert_not_equal scoped_client.stack_id, other_stack.id

  get :show, params: { stack_id: other_stack.to_param, token: scoped_client.authentication_token }

  # Expected (secure) behavior: request for a stack outside the token's scope is rejected
  assert_response :not_found # or :forbidden

  # Own stack still works
  get :show, params: { stack_id: @stack.to_param, token: scoped_client.authentication_token }
  assert_response :ok
end
```
Currently this test fails: the request for `other_stack` returns `200 OK` with that stack's CCMenu XML, proving the scope is not enforced.

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L22-31)
```ruby
      def show
        latest_deploy = stack.deploys_and_rollbacks.last || NoDeploy.new
        render('shipit/ccmenu/project', formats: [:xml], locals: { stack:, deploy: latest_deploy })
      end

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
