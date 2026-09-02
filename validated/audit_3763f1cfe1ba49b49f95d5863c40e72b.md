### Title
Stack-Scoped API Token Bypasses Its Own Authorization Scope in `Api::CCMenuController` - (File: `app/controllers/shipit/api/ccmenu_controller.rb`)

### Summary
This is a valid analog of the reported re-entrancy class: both bugs are "trust-binding" failures where a component reads/acts on a value that bypasses the check meant to constrain it. In the original report, the external call happens before the state that gates further withdrawal is committed. Here, `Api::CCMenuController` authenticates a caller's `ApiClient` token but then resolves the target `Stack` through a path that ignores the very scope binding (`ApiClient#stack_id`) that the token was created to enforce, breaking the equality: **stack a token authorizes == stack the request touches**.

### Finding Description
`ApiClient` records can be (and are, per fixtures) scoped to a single stack via `belongs_to :stack, optional: true` and the `stack_id` column, as shown by the `here_come_the_walrus` fixture: `stack: shipit`, `permissions: ['read:stack']` [1](#0-0) .

The generic `Api::BaseController` enforces this binding for every normal API endpoint: `stacks` is restricted to `Stack.where(id: current_api_client.stack_id)` whenever the client has a `stack_id`, and `stack` is derived from that restricted relation via `stacks.from_param!(params[:stack_id])` [2](#0-1) . This is confirmed by the test asserting a stack-scoped client only ever sees its own stack [3](#0-2) .

`Api::CCMenuController`, however, overrides `stack` to bypass that scoped relation entirely and resolve **any** stack directly from `Stack.from_param!(params[:stack_id])`, using the unrestricted `Stack` model instead of the client-scoped `stacks` method: [4](#0-3) 

`require_permission :read, :stack` only checks that the token carries the `read:stack` string permission via `ApiClient#check_permissions!` [5](#0-4) ; it never re-validates that the specific `stack_id` param matches `current_api_client.stack_id`. Because `authenticate_api_client` in this controller also accepts the token from a `token` query-string parameter [6](#0-5) , a token that is legitimately restricted to one stack (e.g., handed to a public CI status widget) can be replayed with a different `stack_id` in the URL to read another stack's build/deploy state.

### Impact Explanation
Before the attack: an `ApiClient` scoped to Stack A (`stack_id = A`, `permissions: ['read:stack']`) can only read Stack A's state through every other API endpoint, because they all funnel through `Api::BaseController#stacks`/`#stack`.
After the attack: the same token, submitted to `GET /api/*stack_id/ccmenu` with an arbitrary `stack_id = B`, returns Stack B's name, activity, `lastBuildStatus`, `lastBuildLabel`, `lastBuildTime`, `webUrl`, and lock status — none of which the token was authorized to see. This is an unauthorized read of another stack's task/deploy state, matching the in-scope "High" impact category (unauthenticated/unauthorized read of stack state, task streams, or deploy output) via a scope-confused, but validly-signed, token.

### Likelihood Explanation
Requires possession of any valid `ApiClient` token scoped to a single stack (a routine, low-privilege credential frequently embedded in CI dashboards, chat bots, or CCMenu/CI status widgets) — no repository write access, GitHub App key, or session is needed. The `stack_id` parameter is fully attacker-controlled in the URL path, making exploitation trivial once such a token is obtained.

### Recommendation
Have `Api::CCMenuController#stack` resolve the stack through the same client-scoped `stacks` relation used elsewhere (`stacks.from_param!(params[:stack_id])`) instead of calling `Stack.from_param!` directly, so the `ApiClient#stack_id` binding is enforced consistently across all API controllers.

### Proof of Concept
1. As an admin, create (or note the existence of) an `ApiClient` scoped to Stack A with `permissions: ['read:stack']` (mirrors the `here_come_the_walrus` fixture) and obtain its `authentication_token`.
2. Issue: `GET /api/<stack-B-owner>/<stack-B-repo>/<stack-B-env>/ccmenu?token=<stack-A-scoped-token>`
3. Observe HTTP 200 with Stack B's CCMenu XML (name, `lastBuildStatus`, `lastBuildLabel`, etc.), even though the token's `stack_id` only authorizes Stack A — confirmed by the fact that `Api::CCMenuController#stack` uses `Stack.from_param!` instead of the scoped `stacks` method used by every other controller [4](#0-3) .

### Citations

**File:** test/fixtures/shipit/api_clients.yml (L12-17)
```yaml
here_come_the_walrus:
  name: Here Come The Walrus
  creator: walrus
  stack: shipit
  permissions:
    - 'read:stack'
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

**File:** test/controllers/api/stacks_controller_test.rb (L217-223)
```ruby
      test "an api client scoped to a stack will only see that one stack" do
        authenticate!(:here_come_the_walrus)
        get :index
        assert_json do |stacks|
          assert_equal 1, stacks.size
        end
      end
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L27-36)
```ruby
      private

      def stack
        @stack ||= Stack.from_param!(params[:stack_id])
      end

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
