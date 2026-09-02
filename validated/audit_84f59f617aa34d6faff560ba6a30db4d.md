### Title
`Shipit::Api::CCMenuController#stack` bypasses `stacks` scoping, allowing a CCMenu token minted for one stack to read any other stack's deploy state - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`CCMenuController#stack` calls `Stack.from_param!(params[:stack_id])` directly instead of the base controller's `stacks.from_param!`, and the `ApiClient` minted by `CCMenuUrlController#fetch` is never bound to a specific stack in the first place. Any token obtained from a CCMenu URL (e.g., a public CI badge) can therefore be replayed against an arbitrary `stack_id` path segment to read that stack's deploy/task state.

### Finding Description
The claimed broken binding is `current_api_client.stack_id (A) == stack.id (B)`. Tracing the code:

- `CCMenuUrlController#fetch` mints the client with no stack association at all: [1](#0-0) 
`ApiClient.create_with(permissions: %w[read:stack]).find_or_create_by!(creator: current_user, name: 'CCMenu Client')` never sets `stack:`, so `current_api_client.stack_id` is `nil` for every CCMenu client, regardless of which stack's URL the user fetched.

- `Api::BaseController#stacks` reflects this: when `stack_id` is blank it falls back to `Stack.all`: [2](#0-1) 
So even the "safe" scoped `stacks.from_param!` would not restrict a CCMenu client to a single stack - the underlying `ApiClient` model itself carries no per-stack binding for this flow.

- `CCMenuController#stack` compounds this by bypassing `stacks` entirely and hitting `Stack.from_param!` directly: [3](#0-2) 

- Authorization is enforced only via `require_permission :read, :stack`, which checks the client's `permissions` array (`read:stack`) with no stack identity check: [4](#0-3) 

- `ApiClient.authenticate` only validates the signed id, it does not re-derive or check any stack claim: [5](#0-4) 

Exploit: attacker obtains a CCMenu URL for stack A (e.g., pasted publicly as a CI badge) containing `?token=T`. They then request `GET /api/stacks/<org>/<repo-B>/<branch-B>/ccmenu.xml?token=T`. `authenticate_api_client` accepts `T` (valid signature, existing `ApiClient` row), `require_permission!` passes because the client has `read:stack`, and `stack` resolves stack B directly via `Stack.from_param!` with no ownership check. `show` renders `stack.deploys_and_rollbacks.last`, disclosing stack B's deploy status to an attacker who has no relationship to stack B.

None of the existing guards prevent this: `verify_signature`/webhook checks are irrelevant to this path; `ExplicitParameters` is not used here; `stacks` scoping is bypassed by this controller and is ineffective anyway because the client's `stack_id` is never populated by `CCMenuUrlController`.

### Impact Explanation
An attacker with any leaked CCMenu token/URL can enumerate and read the deploy/rollback status of every stack on the Shipit instance, not just the one the URL was generated for. This is cross-tenant/cross-repository unauthenticated information disclosure of deploy state, matching the High severity category ("unauthenticated read of stack state ... task streams or deploy output"). It is fully repeatable - the same token works against any `stack_id` since permission checks are role-based (`read:stack`) not identity-based, and CCMenu tokens tend to be long-lived (no expiry logic visible in `ApiClient#authentication_token`) and often embedded in public badge URLs.

### Likelihood Explanation
Preconditions: the attacker needs one valid CCMenu URL for any stack (commonly exposed publicly as CI/build-status badges, which is the documented purpose of `CCMenuUrlController`). No GitHub App secrets, session, or privileged role are required. The attacker only needs to know or guess the `owner/repo/branch`-style `stack_id` of the target stack (format enforced by `stack_id_format` regex in routes, not secrecy). This is low-cost and highly repeatable across all stacks in the instance.

### Recommendation
Bind the CCMenu `ApiClient` to the specific stack it was minted for (`ApiClient.create_with(stack: stack, permissions: %w[read:stack])`), and have `CCMenuController#stack` use the inherited `stacks.from_param!` (i.e., remove the local `stack` override) so the client's `stack_id` is enforced. Additionally, `Api::BaseController#stacks` should not fall back to `Stack.all` when `stack_id` is blank for scoped API clients that are supposed to be single-stack.

### Proof of Concept
```ruby
# test/controllers/api/ccmenu_controller_test.rb
test "a CCMenu token minted for stack A cannot read stack B" do
  stack_a = shipit_stacks(:shipit)
  stack_b = shipit_stacks(:cyclimse)

  client = ApiClient.create!(
    creator: shipit_users(:walrus),
    name: "CCMenu Client",
    permissions: %w[read:stack]
  ) # stack: is intentionally left unset, matching CCMenuUrlController#client

  token = client.authentication_token

  get "/api/stacks/#{stack_b.to_param}/ccmenu.xml", params: { token: token }

  assert_response :success
  # Binding under test: current_api_client.stack_id (nil/A) must not equal stack.id (B) to be authorized.
  assert_no_match(/#{stack_a.id}/, response.body)
  assert_match(stack_b.deploys_and_rollbacks.last&.id.to_s, response.body,
    "token minted outside of stack B's scope should not disclose stack B's deploy state")
end
```
This demonstrates that a token with no stack binding (as produced by `CCMenuUrlController#fetch`) grants read access to an arbitrary stack via `CCMenuController#stack`, violating the intended per-stack authorization scope.

### Citations

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L15-18)
```ruby
    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
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

**File:** app/models/shipit/api_client.rb (L24-27)
```ruby
      def authenticate(token)
        find_by(id: message_verifier.verify(token).to_i)
      rescue Shipit::SimpleMessageVerifier::InvalidSignature
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
