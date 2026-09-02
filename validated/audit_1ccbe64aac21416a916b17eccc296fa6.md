### Title
CCMenu API token minted for one stack grants read access to any other stack's deploy status - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Api::CCMenuController#stack` bypasses the stack-scoping that `BaseController` normally enforces, and `check_permissions!` only validates the generic `read:stack` permission string with no stack-id comparison. Combined with `CCMenuUrlController#client`, which mints/reuses an `ApiClient` without ever binding it to a specific `stack_id`, any valid CCMenu token for stack A can be replayed against `Api::CCMenuController#show` for any other stack B.

### Finding Description
The claimed binding: permission checked (`"read:stack"`) == permission required (`"read:stack" scoped to stack A`) is **FALSE**, and this divergence is exploitable.

- `BaseController#stack` normally scopes lookups through `stacks`, which filters by `current_api_client.stack_id` when present: `app/controllers/shipit/api/base_controller.rb#L74-L80` [1](#0-0) .
- `Api::CCMenuController` overrides `stack` and drops this scoping entirely, resolving the stack directly from `params[:stack_id]` with no reference to `current_api_client` at all: [2](#0-1) .
- The only permission gate is `require_permission :read, :stack`, which calls `current_api_client.check_permissions!(:read, :stack)` — a check against the literal string `"read:stack"` in the `permissions` array, with no comparison of `stack_id`: [3](#0-2) , [4](#0-3) , [5](#0-4) .
- The token minted by `CCMenuUrlController#fetch` is produced via `ApiClient.create_with(permissions: %w[read:stack]).find_or_create_by!(creator: current_user, name: 'CCMenu Client')` — note that no `stack:` attribute is ever assigned, so `stack_id` on this `ApiClient` record is left `nil`: [6](#0-5) . This means the *same* client record (keyed only by creator + name) is reused for every stack that user fetches a CCMenu URL for, and it is never stack-scoped in the database to begin with.
- `authenticate_api_client` in `CCMenuController` authenticates purely from `params[:token]` via `ApiClient.authenticate`, which only verifies the signed id — it performs no scope check either: [7](#0-6) , [8](#0-7) .

Exploit flow: An authenticated Shipit user (attacker) with read access to stack A visits `CCMenuUrlController#fetch` for stack A, obtaining a CCMenu URL like `.../api/stacks/A/ccmenu.xml?token=<T>`. Because the underlying `ApiClient` has `stack_id = nil` and permission is the generic string `"read:stack"`, the attacker can simply change the URL path segment to stack B (`.../api/stacks/B/ccmenu.xml?token=<T>`) and `Api::CCMenuController#show` will render stack B's build/deploy status XML, even though the attacker has no access rights to stack B whatsoever. Neither `authenticate_api_client`, `require_permission`, nor the overridden `stack` method perform any check that the token's originating stack matches the requested `stack_id`.

Existing guards checked and found insufficient: `require_permission!` only checks the permission string, not scope; `stacks`/`stack` scoping exists in `BaseController` but is bypassed by `CCMenuController`'s override; `ApiClient.authenticate` only validates the signature/id, not scope.

### Impact Explanation
An attacker who is a legitimate collaborator on any single stack (even a public/low-sensitivity one) can enumerate and read the CI/deploy build status (`lastBuildStatus`, `lastBuildLabel`, `activity`, lock state, etc.) of **any other stack** hosted on the same Shipit instance, including private/internal repositories they have no access to. This is a cross-tenant unauthorized read of deploy state, matching the "High - unauthenticated/escalated read of stack state" impact category. It is fully repeatable: the token does not expire per-stack, and the attacker can iterate over arbitrary `stack_id` values to harvest deploy status for the whole instance.

### Likelihood Explanation
Preconditions: the attacker must have a legitimate Shipit login and be able to reach `CCMenuUrlController#fetch` for at least one stack (i.e., be a normal authorized user of at least one repository on the instance — not an anonymous internet attacker with zero Shipit access). Given that precondition, the attack costs a single authenticated request plus changing a URL parameter — no secrets, signing keys, or privileged roles are needed. This is trivial and highly likely for any multi-tenant Shipit deployment where users are scoped to specific repositories/stacks.

### Recommendation
- Have `CCMenuUrlController#client` bind the created `ApiClient` to the specific stack (`stack: stack`) instead of a shared, unscoped client per user.
- Restore stack-scoping in `Api::CCMenuController#stack` by using the inherited `stacks` scope (i.e., `stacks.from_param!(params[:stack_id])`) instead of `Stack.from_param!(params[:stack_id])` directly, so a client whose `stack_id` is set can only resolve its own stack.

### Proof of Concept
```ruby
# test/controllers/api/ccmenu_controller_test.rb
test "a token minted for one stack cannot render another stack's ccmenu xml" do
  stack_a = shipit_stacks(:shipit)
  stack_b = Stack.create!(repository: Repository.new(owner: "foo", name: "bar"), branch: 'main')

  # Simulate a CCMenu token minted for stack_a only (no stack scoping, as produced by
  # CCMenuUrlController#client)
  scoped_client = ApiClient.create!(creator: @user, name: 'CCMenu Client', permissions: %w[read:stack])

  get :show, params: { stack_id: stack_b.to_param, token: scoped_client.authentication_token }

  # Binding under test: token's originating stack (stack_a) == requested stack (stack_b) should be false,
  # so this request should be rejected (403/404), not rendered.
  assert_response :forbidden # or :not_found, per intended fix
  assert_not_includes response.body, stack_b.to_param
end
```
Currently this test fails (returns `200 OK` with stack B's XML), demonstrating the vulnerability.

### Citations

**File:** app/controllers/shipit/api/base_controller.rb (L18-22)
```ruby
      class << self
        def require_permission(operation, scope, options = {})
          before_action(options) { require_permission!(operation, scope) }
        end
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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L27-31)
```ruby
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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L7-18)
```ruby
    def fetch
      uri = URI(api_stack_ccmenu_url(stack_id: stack.to_param))
      uri.query = { 'token' => client.authentication_token }.to_query
      render(json: { ccmenu_url: uri.to_s })
    end

    private

    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```
