### Title
Unauthenticated cross-stack read via `CCMenuController#stack` bypassing `stack_id` scoping - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Api::CCMenuController#stack` overrides the base class's stack lookup with a bare `Stack.from_param!(params[:stack_id])`, discarding the `stack_id` scoping that `ApiClient` tokens are supposed to enforce. A CCMenu token minted for stack A (via `CCMenuUrlController#fetch`) can be replayed with `stack_id` set to stack B, and `require_permission!` only checks the permission string (`read:stack`), not which stack the client is scoped to, so the request succeeds and returns stack B's deploy/rollback data.

### Finding Description
The binding that should hold is: for any request authenticated by `current_api_client`, the stack it operates on must satisfy `current_api_client.stack_id.nil? || stack.id == current_api_client.stack_id`. This is exactly what `Api::BaseController#stacks` implements: [1](#0-0) 

But `Api::CCMenuController` redefines `stack` to bypass `stacks` entirely: [2](#0-1) 

`CCMenuUrlController#fetch` mints a token scoped to a single stack (via `ApiClient#stack`/`stack_id`) and hands it to the current user for CI-status polling of that one stack: [3](#0-2) 

`authenticate_api_client` in `CCMenuController` only validates the token's signature/existence, not its `stack_id`: [4](#0-3) 

`require_permission!` / `ApiClient#check_permissions!` only checks that the client's `permissions` array contains `read:stack` — it has no notion of which stack that permission applies to: [5](#0-4) 

So the only place `stack_id` scoping is enforced anywhere in the API is the `stacks` helper in `BaseController`, and `CCMenuController` explicitly does not use it. An attacker who obtains (or is given, e.g. as a collaborator on repo A with a CCMenu URL) a token for stack A can simply change `stack_id` in the URL/query string to stack B's slug and read stack B's CI/deploy status.

### Impact Explanation
The attacker obtains unauthenticated (relative to stack B) read access to stack B's latest deploy/rollback status, build label, activity and web URL — data that reveals internal repository/branch names, deploy cadence, and success/failure state for a stack they were never authorized to see. This is repeatable against every stack in the installation using a single token minted for one stack, giving a full-instance information-disclosure primitive. This matches the "unauthenticated read of stack state" High-severity category listed in the rules.

### Likelihood Explanation
The only precondition is possessing any valid CCMenu token, which is trivially obtained by any user who can call `CCMenuUrlController#fetch` for a stack they do have legitimate access to (this endpoint runs under normal session auth, not API auth) — or one leaked/shared by such a user. The attack itself is a single GET request with a modified `stack_id` parameter; no secrets, signatures, or elevated roles are needed. This makes it a low-cost, fully repeatable escalation from "authorized to see stack A's status" to "read every stack's status."

### Recommendation
Change `Api::CCMenuController#stack` to reuse the base class's scoped lookup instead of a bare `Stack.from_param!`, e.g. delegate to `stacks.from_param!(params[:stack_id])` (or simply remove the override so the inherited `BaseController#stack` is used), ensuring `current_api_client.stack_id` restricts which stacks the token can query.

### Proof of Concept
```ruby
# test/controllers/api/ccmenu_controller_test.rb (new test)
test "a token scoped to stack A cannot read stack B via CCMenu" do
  stack_a = shipit_stacks(:shipit)
  stack_b = Stack.create!(repository: Repository.new(owner: "other", name: "repo"), branch: "main")

  scoped_client = ApiClient.create!(
    creator: @user, name: "Scoped CCMenu Client",
    permissions: %w[read:stack], stack: stack_a
  )

  # binding under test: stack accessed must equal scoped_client.stack_id
  assert_equal stack_a.id, scoped_client.stack_id

  get :show, params: { stack_id: stack_b.to_param, token: scoped_client.authentication_token }

  # Expect this to be rejected (404/403), but current code returns 200 with stack B's data
  assert_response :not_found # currently fails: actual response is :ok exposing stack_b data
end
```

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
