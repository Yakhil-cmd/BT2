Confirmed vulnerability. `ApiClient.create_with(permissions: %w[read:stack]).find_or_create_by!(creator: current_user, name: 'CCMenu Client')` in `CCMenuUrlController#client` never sets `stack:`, so the minted `ApiClient` record has `stack_id == nil` [1](#0-0) . `Api::BaseController#stacks` treats a nil `stack_id` as unrestricted: `current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all` [2](#0-1) , and `Api::CCMenuController#stack` resolves via `Stack.from_param!` directly (not even via the `stacks` scope, but the effect is the same since the token carries no stack restriction at all) [3](#0-2) . `check_permissions!` only checks the `read:stack` string permission, never the stack identity [4](#0-3) .

The binding claimed by the URL — `/ccmenu/:stack_id` grants a token scoped to that `:stack_id` — does not hold: the token is scoped to nothing, and is also **shared and cached** across all stacks, since `find_or_create_by!(creator: current_user, name: 'CCMenu Client')` looks up by `creator` + fixed `name` only, ignoring `stack`. So the very first time any user calls `fetch` for any stack, a single global `ApiClient` for that user is created, and the same token is returned for every subsequent stack's CCMenu URL for that user. That token, when used against `Api::CCMenuController#show` for any `stack_id`, will succeed with `200 OK` because `stack` permission checking is purely by permission string, not stack identity.

This is a real, reachable, engine-internal bug (not requiring secrets), matching the "unauthenticated read of stack state" High severity impact bucket (arguably borderline since it requires having legitimately visited a stack's settings page once, but the read authorization scope is broken regardless of that page's stack).

### Title
CCMenu URL token authorizes reads of all stacks, not the stack it was minted for - (File: app/controllers/shipit/ccmenu_url_controller.rb)

### Summary
`CCMenuUrlController#client` creates an `ApiClient` with `read:stack` permission but never sets `stack:`, leaving `stack_id` nil. Because `Api::BaseController#stacks` returns `Stack.all` when `stack_id` is nil, and `Api::CCMenuController` performs no additional stack-identity check, the token minted from `/ccmenu/:stack_id` for one stack authorizes `GET /api/ccmenu/:any_stack_id` for every stack, and — due to `find_or_create_by!` keying only on `creator`/`name` — the exact same token is reused/returned for all stacks a given user visits.

### Finding Description
Binding claimed: `token minted at GET /ccmenu/:stack_id` == `authorization limited to Stack.from_param!(stack_id)`.

Actual code:
- `CCMenuUrlController#client` ( [1](#0-0) ) builds/finds an `ApiClient` scoped only by `creator` and `name: 'CCMenu Client'`, with `permissions: %w[read:stack]`, never passing `stack:`.
- `ApiClient` model has an optional `belongs_to :stack` ( [5](#0-4) ) that stays `nil` here.
- `Api::BaseController#stacks` ( [2](#0-1) ) is the only place that would have restricted a request to a single stack via `current_api_client.stack_id`, but `Api::CCMenuController#stack` bypasses even that by calling `Stack.from_param!(params[:stack_id])` directly ( [3](#0-2) ), with zero dependency on the client's `stack_id`.
- `ApiClient#check_permissions!` only checks the permission string `read:stack`, never stack identity ( [4](#0-3) ).

Attacker flow: a user with legitimate access to stack A's settings page fetches the CCMenu URL (`GET /ccmenu/stack_A`), receiving a token. That user (or anyone who obtains the token, e.g. by pasting it into a public CI status page/README as CCMenu URLs are designed to be embedded) can call `GET /api/ccmenu/stack_B?token=...` for any other stack `B` and receive `200 OK` with stack B's deploy/build status — data from a stack the token was never scoped to.

No existing guard prevents this: `require_permission :read, :stack` only checks the permission string is present; there's no `stack_id` comparison anywhere in this path.

### Impact Explanation
Any CCMenu token — designed to be embedded in public CI dashboards/badges — grants unauthenticated read access (build status, last build label/time, activity, web URL) to **every** stack in the Shipit instance, not just the one it was displayed for. This matches "unauthenticated read of stack state" (High). It does not reach Critical since `read:stack` for CCMenu only exposes deploy/build status (name, activity, lastBuildStatus/Label/Time, webUrl) via the `shipit/ccmenu/project` view, not secrets or write actions.

### Likelihood Explanation
Trivial to trigger: any user who can view a single stack's settings page (which is a normal, low-privilege UI feature) obtains a token that works against all stacks. No GitHub or Shipit secrets are needed to exploit once the token is obtained (only knowledge of it, which is expected to be shared per CCMenu's design as an embeddable badge URL). High feasibility, fully repeatable.

### Recommendation
Scope the `ApiClient` to the stack: pass `stack: stack` in `create_with`, add `stack` to the `find_or_create_by!` lookup key (or a per-stack name), and add a `current_api_client.stack.nil? || current_api_client.stack == stack` (or reuse `stacks` scope in `Api::CCMenuController#stack`) check so a stack-bound token cannot be replayed against another stack.

### Proof of Concept
Minitest (`test/controllers/api/ccmenu_controller_test.rb` style, illustrative — currently out-of-scope path but demonstrates the assertions needed):
```ruby
test "a CCMenu token minted for stack_a authorizes reads of stack_b" do
  stack_a = shipit_stacks(:shipit)
  stack_b = Stack.create!(repository: Repository.new(owner: "foo", name: "bar2"), branch: 'main')
  user = shipit_users(:walrus)

  # simulate CCMenuUrlController#fetch for stack_a
  client = ApiClient.create_with(permissions: %w[read:stack])
                     .find_or_create_by!(creator: user, name: 'CCMenu Client')
  token = client.authentication_token

  get :show, params: { stack_id: stack_b.to_param, token: token }
  assert_response :ok # proves token minted via stack_a's URL authorizes stack_b
end
```
Both sides of the binding: `stack encoded in /ccmenu/:stack_id at mint time == stack_a`; `stack actually authorized by resulting token == Stack.all (unrestricted)`. They diverge, confirming the vulnerability.

### Citations

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L15-18)
```ruby
    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```

**File:** app/controllers/shipit/api/base_controller.rb (L74-76)
```ruby
      def stacks
        @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
      end
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L29-31)
```ruby
      def stack
        @stack ||= Stack.from_param!(params[:stack_id])
      end
```

**File:** app/models/shipit/api_client.rb (L8-8)
```ruby
    belongs_to :stack, optional: true
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
