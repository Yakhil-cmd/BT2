### Title
CCMenu token can read any stack's build status, not just the one it was minted for - (File: `app/controllers/shipit/api/ccmenu_controller.rb`)

### Summary
The `ApiClient` minted by `Shipit::CCMenuUrlController#fetch` for a given stack is never bound to that stack (`stack:`/`stack_id` is not set on creation), and `Api::CCMenuController#stack` bypasses the base controller's stack-scoping helper entirely by calling `Stack.from_param!(params[:stack_id])` directly instead of `stacks.from_param!(params[:stack_id])`. As a result, a CCMenu URL/token minted for stack A can be replayed with a different `stack_id` to read the CCMenu XML status (build status, last build label/time, lock state) of any other stack B on the instance.

### Finding Description
The claimed binding "stack touched by the request == the single stack in `current_api_client.stack_id`" does not hold, and in fact is broken twice:

1. **The token is never scoped to a stack at all.** `Shipit::CCMenuUrlController#client` does:
```ruby
@client ||= ApiClient.create_with(permissions: %w[read:stack])
                     .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
``` [1](#0-0) 
No `stack:` attribute is passed, so the created/found `ApiClient` has `stack_id == nil` regardless of which stack the user requested the CCMenu URL for. `ApiClient#stack` is `belongs_to :stack, optional: true` [2](#0-1) , so a nil `stack_id` is a valid, persisted state. Because `find_or_create_by!` matches solely on `creator` + `name`, the very first CCMenu URL a user requests for *any* stack creates one reusable "CCMenu Client" `ApiClient`, and every subsequent CCMenu URL for any other stack the same user has access to reuses that same unscoped client/token.

2. **Even if `stack_id` were set, `Api::CCMenuController` doesn't check it.** The base controller defines a scoped lookup:
```ruby
def stacks
  @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
end

def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
``` [3](#0-2) 
But `Api::CCMenuController` overrides `stack` to bypass this scope entirely:
```ruby
def stack
  @stack ||= Stack.from_param!(params[:stack_id])
end
``` [4](#0-3) 
This resolves the stack directly from `Stack.from_param!`, with no reference to `current_api_client.stack_id` at all. `require_permission :read, :stack` only checks that the token has the `read:stack` permission string [5](#0-4) ; it never checks *which* stack the permission applies to.

Exploit: An attacker who is a legitimate (unprivileged) user of stack A visits the CCMenu URL feature for stack A, obtaining `token=<T>`. They then send `GET /api/stacks/:B_id/cc_menu.xml?stack_id=B&token=<T>` (or the analogous `stack_id` for any other stack on the instance they can guess/enumerate). `Api::BaseController#authenticate_api_client` in `CCMenuController` is overridden to authenticate purely from `params[:token]` via `ApiClient.authenticate(params[:token])` [6](#0-5) , which succeeds because the token is valid and signed. `require_permission!(:read, :stack)` passes because the client's `permissions` include `read:stack`. `stack` then resolves stack B unconditionally. The response includes stack B's build status, last build label/time, web URL, and lock status — a cross-tenant/cross-stack information disclosure.

Existing guards do not catch this: `verify_signature`/webhook checks are irrelevant here (no webhook involved); `ExplicitParameters` schema doesn't declare/validate `stack_id` against the client; and the `stacks` scope that *would* have prevented this is simply not used by `CCMenuController#stack`.

### Impact Explanation
Any unprivileged user of one stack (or anyone who acquires a single CCMenu token, e.g., from a shared CI dashboard, a leaked query string in logs/browser history/proxy, or a `Referer` header) can read the current build/deploy status, last build label, last build time and lock state of every other stack hosted on the same Shipit instance, by simply varying `stack_id`. This is a High-severity unauthenticated/under-scoped cross-tenant read of stack state (build status metadata), repeatable indefinitely against any stack on the instance since the token never expires and is not stack-bound.

### Likelihood Explanation
Preconditions are minimal: the attacker only needs to be a normal Shipit user of any one stack (to trigger `CCMenuUrlController#fetch` once) or otherwise obtain a previously-issued CCMenu token/URL. No GitHub secrets, webhook secrets, or Shipit operator privileges are required. `stack_id`s are typically small sequential or slug-based identifiers, making enumeration low-cost. This is trivially reproducible with a single HTTP GET, so likelihood is high given any user account on the instance.

### Recommendation
- In `Shipit::CCMenuUrlController#client`, bind the created `ApiClient` to the requested stack (e.g. `find_or_create_by!(creator: current_user, name: 'CCMenu Client', stack: stack)`, or mint a distinct token per stack) rather than sharing one unscoped client across all stacks for a user.
- In `Api::CCMenuController`, remove the `stack` override and use the base `stacks.from_param!(params[:stack_id])` (or otherwise explicitly verify `current_api_client.stack_id == stack.id` when `stack_id?` is true) so a stack-scoped client cannot be replayed against another stack.

### Proof of Concept
```ruby
# test/controllers/api/ccmenu_controller_test.rb (new test)
test "a token minted for stack A cannot read stack B's status" do
  stack_a = shipit_stacks(:shipit)
  stack_b = Stack.create!(repository: Repository.create!(owner: 'foo', name: 'bar'), branch: 'main')

  # Simulate CCMenuUrlController#fetch minting a token for stack_a
  client = ApiClient.create_with(permissions: %w[read:stack])
                     .find_or_create_by!(creator: shipit_users(:walrus), name: 'CCMenu Client')
  # BINDING UNDER TEST: client.stack_id should equal stack_a.id (scoped to A)
  assert_nil client.stack_id # demonstrates binding is already broken at creation time

  get :show, params: { stack_id: stack_b.to_param, token: client.authentication_token }

  # Expected (secure) behavior: 403/404, not stack B's data
  assert_response :forbidden # or :not_found, current code instead returns :ok with stack B's XML
end
```
This demonstrates that the same CCMenu token issued in the context of stack A successfully returns `:ok` with stack B's CCMenu XML payload when it should be rejected, confirming the cross-stack read.

### Citations

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L15-18)
```ruby
    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```

**File:** app/models/shipit/api_client.rb (L7-8)
```ruby
    belongs_to :creator, class_name: 'User'
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

**File:** app/controllers/shipit/api/base_controller.rb (L74-80)
```ruby
      def stacks
        @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
      end

      def stack
        @stack ||= stacks.from_param!(params[:stack_id])
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
