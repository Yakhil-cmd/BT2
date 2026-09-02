### Title
Api::CCMenuController#stack bypasses stack_id-scoped `stacks`, letting a stack-scoped ApiClient read any stack's CC Menu XML - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Shipit::Api::BaseController#stacks` scopes queries to `current_api_client.stack_id` when the token has one set, and `#stack` in the base class correctly calls `stacks.from_param!`. `Shipit::Api::CCMenuController` overrides `#stack` and calls `Stack.from_param!(params[:stack_id])` directly against the unscoped `Stack` relation, so the stack_id restriction on the API token is never applied for this endpoint.

### Finding Description
The broken binding: `current_api_client.stack_id == A.id` should imply that every stack resolved during the request also has `id == A.id` (i.e. `stack.id ∈ stacks.pluck(:id)`), where `stacks` is `Stack.where(id: current_api_client.stack_id)` per [1](#0-0) .

`CCMenuController` overrides `#stack` and resolves it independently: [2](#0-1) 
This calls `Stack.from_param!` on the unscoped `Stack` model, not on `stacks` (the scoped relation defined in the base class), so `params[:stack_id]` can name any stack in the system regardless of the token's `stack_id`.

Authorization for this controller is solely `require_permission :read, :stack`, which only checks that the token's `permissions` array contains the string `"read:stack"` via `ApiClient#check_permissions!`: [3](#0-2) 
This check is scope-name-only; it does not verify which stack the token is bound to. The stack_id restriction is enforced exclusively through the `stacks` helper, and only that helper — never `Stack` directly — encodes the binding. Since `CCMenuController#stack` never calls `stacks`, `@stacks` is never even memoized on this controller, and the stack_id restriction added in `BaseController#stacks` is dead code for this endpoint.

Attacker/exploit flow: an operator mints an `ApiClient` (e.g. via the stack settings UI, which generates per-stack CI tokens for the CC Menu URL feature — see `app/controllers/shipit/ccmenu_url_controller.rb` and `app/views/shipit/stacks/settings.html.erb`) scoped to stack A (`stack_id = A.id`) with `read:stack` permission. That token's owner (an "attacker" relative to stack B) sends `GET /api/1/stacks/:stack_id/cc_menu.xml?token=<A's token>` with `:stack_id` in the URL naming stack B. `CCMenuController#authenticate_api_client` authenticates the token fine (token identifies client, not which stack) at [4](#0-3) ; `require_permission :read, :stack` passes because the token has `"read:stack"` in its permissions, irrespective of `stack_id`; `#stack` then resolves stack B via unscoped `Stack.from_param!`, and `#show` renders stack B's CC Menu XML (deploy status) at [5](#0-4) .

No other guard intervenes: `verify_signature`/webhook checks are irrelevant (this is a plain HTTP GET, not a webhook), `ExplicitParameters` isn't used for `:stack_id` in this controller, and `Stack#from_param!`/`Stack` validations do not consult `ApiClient` at all.

### Impact Explanation
A token intentionally scoped to a single stack (commonly distributed as a per-stack "CC Menu URL" credential, treated as low-trust since it's often embedded in CI dashboards or shared widgets) can be used to read the deploy/build status (`stack.deploys_and_rollbacks.last`, running state, last deploy end time) of any other stack in the Shipit instance, including stacks belonging to unrelated repositories/teams. This is unauthenticated-relative-to-scope read of task/deploy state for another tenant, matching the High severity category ("unauthenticated read of stack state, task streams or deploy output" — here, cross-tenant read via a token that should be confined to one stack). It is fully repeatable: the attacker can enumerate `:stack_id` values (numeric IDs or repo/env-based params, depending on `Stack.from_param!`'s lookup key) to read every stack's CC Menu status with a single scoped token.

### Likelihood Explanation
Preconditions: attacker needs possession of *any* valid API token with `read:stack` permission and a non-nil `stack_id` — such tokens are the expected/normal shape for CC Menu integration and are handed out per-stack precisely because they are meant to be narrowly scoped (see `ccmenu_url_controller.rb`). No `api_clients_secret`, session, or GitHub secret is required beyond having one legitimately-scoped token. The only extra "cost" is knowing/guessing another stack's `:stack_id` param, which is low (sequential IDs or discoverable via other means). This makes the issue highly likely to be exploitable wherever CC Menu tokens are distributed to less-trusted parties (e.g., embedded in third-party CI status widgets), which is the tokens' intended use case.

### Recommendation
Change `Shipit::Api::CCMenuController#stack` to resolve through the scoped relation, matching the base controller:
```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```
and remove the redundant override entirely if the base class's `#stack` already does this correctly, so that the `stack_id` scoping in `BaseController#stacks` is the single source of truth for every `Api::*Controller` subclass.

### Proof of Concept
```ruby
# test/controllers/api/ccmenu_controller_test.rb (illustrative)
test "a token scoped to stack A cannot read stack B via cc_menu.xml" do
  stack_a = shipit_stacks(:shipit)
  stack_b = shipit_stacks(:cyclimse)
  refute_equal stack_a.id, stack_b.id

  scoped_client = ApiClient.create!(
    creator: shipit_users(:walrus),
    name: "cc-menu-scoped",
    stack: stack_a,
    permissions: ['read:stack']
  )

  get "/api/1/stacks/#{stack_b.to_param}/cc_menu.xml",
      params: { token: scoped_client.authentication_token }

  # Binding under test: response must not resolve to stack_b
  # (i.e. stack_b.id must not be in the set authorised by scoped_client.stack_id)
  assert_response :not_found # or :forbidden, per fixed behavior
  # Before the fix: assert_response :success, and response body identifies stack_b,
  # proving CCMenuController#stack ignored `stacks` (Stack.where(id: scoped_client.stack_id))
end
```
This proof directly exercises the equality `current_api_client.stack_id (A) == resolved stack.id`, showing it fails (resolves to B) under current code because `CCMenuController#stack` calls `Stack.from_param!` instead of `stacks.from_param!`.

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L22-25)
```ruby
      def show
        latest_deploy = stack.deploys_and_rollbacks.last || NoDeploy.new
        render('shipit/ccmenu/project', formats: [:xml], locals: { stack:, deploy: latest_deploy })
      end
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L29-31)
```ruby
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
