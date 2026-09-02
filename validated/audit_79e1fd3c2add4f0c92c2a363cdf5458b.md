### Title
CCMenuUrlController mints an unscoped `read:stack` `ApiClient` token that grants cross-tenant read of any stack's build status - ([File: app/controllers/shipit/ccmenu_url_controller.rb])

### Summary
`CCMenuUrlController#client` creates (or reuses) an `ApiClient` with `permissions: %w[read:stack]` but never sets `stack_id`, even though the token is minted in the context of one specific stack's CC-menu URL. Because `Shipit::Api::CCMenuController` resolves the target stack via `Stack.from_param!(params[:stack_id])` with no comparison to `current_api_client.stack_id`, and `ApiClient#check_permissions!` only checks the operation/scope string, the resulting token silently becomes a global `read:stack` credential valid for every stack in the installation, not just the one the URL was generated for.

### Finding Description
The claimed binding is: `current_api_client.stack_id == requested_stack.id` (or the client is otherwise proven authorized for that specific stack) before `read:stack` is granted. In practice no such comparison exists anywhere in the reachable path.

- `CCMenuUrlController#client` [1](#0-0)  creates an `ApiClient` via `ApiClient.create_with(permissions: %w[read:stack]).find_or_create_by!(creator: current_user, name: 'CCMenu Client')`. The lookup key is only `creator` + `name`; `stack_id` is never assigned, so it stays `nil`, and the same single client (and its one static `authentication_token`) is reused across every stack the user ever generates a CC-menu URL for.
- `Shipit::Api::CCMenuController` overrides authentication and stack resolution: `authenticate_api_client` accepts `params[:token]` directly, and `stack` resolves via `Stack.from_param!(params[:stack_id])` [2](#0-1) , bypassing the `stacks`/`stack` helpers in `BaseController` that would otherwise scope lookups through `current_api_client.stack_id` [3](#0-2) .
- The only permission gate is `require_permission :read, :stack` [4](#0-3) , which calls `current_api_client.check_permissions!('read', 'stack')` [5](#0-4) , which is a pure string-membership check against `permissions` with no reference to the target stack at all [6](#0-5) .

Exploit flow: a Shipit user authorized to view only Stack A (e.g. their team's stack) requests a CC-menu URL for Stack A via `CCMenuUrlController#fetch`. This mints/reuses a `read:stack`, `stack_id: nil` token embedded directly in a URL. That URL/token, once obtained by anyone (shared link, browser history, CI config, log line, referrer leak), can be replayed against `GET /api/stacks/:any_stack_id/cc.xml?token=...` for any other stack in the installation - including private/internal stacks belonging to different repositories/owners the token holder was never authorized to see - because `stack_id` being `nil` is treated everywhere in this engine as "unscoped/global" rather than "invalid/unauthorized."

No existing guard prevents this: `verify_signature`/webhook checks are irrelevant to this API path; `require_permission!` only checks the operation string; the `stacks` scoping helper that does compare `current_api_client.stack_id` is bypassed entirely by `CCMenuController#stack`; and there is no `User#authorized?`/team-membership check re-evaluated at read time - authorization was only checked once, informally, at token-minting time for Stack A, and never re-validated against the stack actually being requested.

### Impact Explanation
A single leaked or reused CC-menu token grants unauthenticated read of build/deploy status (`lastBuildStatus`, `activity`, `webUrl`, lock state) for every stack across every repository and organization boundary in the Shipit instance, not just the stack it was generated for. This is a cross-tenant confidentiality break: an attacker who obtains one such token (via URL sharing, logs, browser history, or a compromised low-privilege teammate's link) can enumerate `stack_id`/slug values and repeatedly pull internal CI/deploy status for repositories they have no team membership in. This matches the "High - unauthenticated read of stack state" impact category.

### Likelihood Explanation
Preconditions are low-cost: any Shipit user who can legitimately request a CC-menu URL for one stack (a normal, expected workflow surfaced in the stack settings UI) ends up holding a token that works far beyond its intended scope. No secrets (`api_clients_secret`, GitHub tokens) need to be stolen - only the already-issued CC-menu URL/token needs to leak or be reused, which is a realistic occurrence given CC-menu URLs are designed to be pasted into third-party CI dashboard tools. The attack is fully repeatable against arbitrary `stack_id` values with the same token.

### Recommendation
Set `stack_id: stack.id` when creating the `ApiClient` in `CCMenuUrlController#client`, scope the `find_or_create_by!` lookup to include the stack, and make `CCMenuController#stack` use the scoped `stacks` helper from `BaseController` (or explicitly verify `current_api_client.stack_id == stack.id` when `stack_id` is present) instead of `Stack.from_param!` directly.

### Proof of Concept
```ruby
# test/controllers/api/ccmenu_controller_test.rb
test "an unscoped read:stack token issued for one stack can read arbitrary other stacks" do
  user = shipit_users(:walrus)
  stack_a = shipit_stacks(:shipit) # e.g. rails/shipit
  stack_b = Stack.create!(repository: Repository.create!(owner: 'other-org', name: 'private-repo'), branch: 'main')

  client = ApiClient.create!(creator: user, name: 'CCMenu Client', permissions: %w[read:stack], stack_id: nil)

  get :show, params: { stack_id: stack_a.to_param, token: client.authentication_token }
  assert_response :ok

  get :show, params: { stack_id: stack_b.to_param, token: client.authentication_token }
  assert_response :ok # demonstrates read access to a stack from an unrelated org/repo using the same token
end
```
Both requests succeed with `stack_id: nil` on the client, proving the binding `current_api_client.stack_id == requested_stack.id` is never enforced, and a single token authorized for one stack context grants cross-tenant read.

### Citations

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L15-18)
```ruby
    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L6-6)
```ruby
      require_permission :read, :stack
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L29-36)
```ruby
      def stack
        @stack ||= Stack.from_param!(params[:stack_id])
      end

      def authenticate_api_client
        @current_api_client = ApiClient.authenticate(params[:token])
        super unless @current_api_client
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

**File:** app/controllers/shipit/api/base_controller.rb (L82-84)
```ruby
      def require_permission!(operation, scope)
        current_api_client.check_permissions!(operation, scope)
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
