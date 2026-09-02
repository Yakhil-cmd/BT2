### Title
CCMenu client token minted for one stack grants read access to every stack's build status - (File: app/controllers/shipit/ccmenu_url_controller.rb)

### Summary
`Shipit::CCMenuUrlController#fetch` mints an `ApiClient` token intended to expose one stack's CI status via CCMenu, but never binds that client to the stack it was generated for. `Shipit::Api::CCMenuController` then authenticates purely by token validity and resolves the target stack straight from `params[:stack_id]` with no scoping check, so any CCMenu token can be replayed against every stack in the installation.

### Finding Description
The claimed binding is:
`{stacks readable with token T minted for stack A}` should equal `{A}`, but it actually equals `{all Stack rows in the installation}`.

- `CCMenuUrlController#fetch` builds the token via [1](#0-0) 
which calls `ApiClient.create_with(permissions: %w[read:stack]).find_or_create_by!(creator: current_user, name: 'CCMenu Client')`. It never sets `stack:` on the client, so `ApiClient#stack_id` stays `nil` for this record even though `ApiClient` supports an optional `belongs_to :stack` for exactly this purpose [2](#0-1) . Because the lookup key is `(creator, name)`, the same unscoped client/token is reused for every stack the same user ever requests a CCMenu URL for.
- `Shipit::Api::CCMenuController` authenticates the token generically: [3](#0-2) 
and resolves the stack directly from the request parameter, bypassing the `stacks` helper in `BaseController` that would otherwise scope results to `current_api_client.stack_id`: [4](#0-3) 
compare with the scoping helper it does not use: [5](#0-4) 
- Even if it did use `stacks`, it would not matter here because the client's `stack_id` is `nil`, and `stacks` falls back to `Stack.all` whenever `stack_id?` is false [6](#0-5) .
- Authorization is enforced only via `require_permission :read, :stack` [7](#0-6) , which checks the static string `"read:stack"` against the client's `permissions` array and has no notion of *which* stack is being accessed [8](#0-7) .

Given a token minted for `Stack A`, an attacker (or the legitimate user reusing their own CC monitoring URL) can request `/api/stacks/<id>/cc.xml?token=<T>` for `id = 1..N` and receive `200 OK` with build status, last commit SHA/label, and lock state for every stack that exists, not just `A`.

### Impact Explanation
This exposes deploy state (branch name, latest build/commit SHA, lock status, success/failure) for every stack in the Shipit installation to anyone holding a single CCMenu token, regardless of which stack that token was originally issued for. This is a cross-tenant/cross-repository disclosure of stack state through an improperly-scoped credential. Per the given severity taxonomy this is best characterized as **High** ("unauthenticated/under-authenticated read of stack state") rather than Critical — it is a read-only information disclosure; it does not achieve RCE, credential exfiltration, or a write/mutation against another repository's stack.

### Likelihood Explanation
No GitHub secrets, session, or privileged role is needed beyond possessing one valid CCMenu token, which is trivially obtainable by any Shipit user with legitimate access to at least one stack (via the "CC menu URL" feature on that stack's settings page), and CCMenu URLs are commonly shared with third-party CI dashboard tools, increasing the chance of leakage. Once obtained, enumeration is a simple GET loop over `/api/stacks/:stack_id/cc.xml` with sequential/known stack identifiers — no rate limiting or per-stack scoping stops it. This is a Rails engine bug, not a GitHub-side condition, so it is fully within scope.

### Recommendation
Bind the CCMenu client to the specific stack when it is created (`ApiClient.create_with(permissions: %w[read:stack], stack: stack).find_or_create_by!(creator: current_user, stack: stack, name: 'CCMenu Client')`), and change `Shipit::Api::CCMenuController#stack` to use the inherited scoped `stacks` helper (`stacks.from_param!(params[:stack_id])`) instead of `Stack.from_param!` directly, so a stack-scoped token can only ever resolve to the stack it was issued for.

### Proof of Concept
Minitest plan (`test/controllers/api/ccmenu_controller_test.rb`):
```ruby
test "a CCMenu token minted for one stack cannot read another stack" do
  stack_a = shipit_stacks(:shipit)
  stack_b = Stack.create!(repository: Repository.new(owner: "other", name: "repo"), branch: "main")

  # Simulate CCMenuUrlController#fetch minting a token for stack_a
  client = ApiClient.create!(creator: shipit_users(:walrus), name: 'CCMenu Client', permissions: %w[read:stack])
  token = client.authentication_token

  # Binding under test: token minted in context of stack_a should NOT resolve stack_b
  get :show, params: { stack_id: stack_b.to_param, token: token }

  assert_response :forbidden # or :not_found — currently fails, actual response is :ok
end
```
Currently this assertion fails because the request returns `200 OK` with `stack_b`'s data, demonstrating the broken binding.

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L6-6)
```ruby
      require_permission :read, :stack
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

**File:** app/controllers/shipit/api/base_controller.rb (L74-80)
```ruby
      def stacks
        @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
      end

      def stack
        @stack ||= stacks.from_param!(params[:stack_id])
      end
```
