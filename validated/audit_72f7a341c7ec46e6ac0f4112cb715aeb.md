### Title
Stack-scoped `ApiClient` tokens can read the CCMenu status of *any* stack, bypassing the token-to-stack binding - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Api::BaseController` restricts a stack-scoped `ApiClient` (one created with a specific `stack_id`) to only operate on that one `Stack` via the `stacks`/`stack` helper methods. `Api::CCMenuController` overrides `#stack` and queries the unscoped `Stack` model directly, so a token that is only supposed to authorize reads of stack A can be used to read the CCMenu (build status, last deploy time, activity) of any other stack B in the Shipit instance.

### Finding Description
`Api::BaseController` establishes the binding "the stack(s) a token authorizes == the stack(s) a request may touch": [1](#0-0) 

`current_api_client.stack_id?` is true whenever the `ApiClient` record has a `stack_id` set (an `ApiClient` `belongs_to :stack, optional: true`), and in that case `stacks` is deliberately narrowed to `Stack.where(id: current_api_client.stack_id)` so that `stack` (`stacks.from_param!(params[:stack_id])`) can never resolve to a different stack, regardless of what `params[:stack_id]` an attacker supplies.

`ApiClient#check_permissions!` only checks the coarse `operation:scope` string (e.g. `read:stack`), it never re-validates which specific stack is being accessed: [2](#0-1) 

So the *only* place enforcing "this token's stack == the stack being read" is the `stacks`/`stack` helper in `BaseController`.

`Api::CCMenuController` bypasses this helper entirely by redefining `stack` to query the global, unscoped `Stack` class: [3](#0-2) 

`require_permission :read, :stack` (line 6) only asserts that the token has the `read:stack` permission string - it does not re-derive `stack` from the scoped `stacks` collection. The `show` action then renders full deploy/build status for whatever `stack_id` param was supplied: [4](#0-3) 

The equality that should hold is:
`stack the ApiClient.stack_id authorizes == stack CCMenuController#stack resolves and renders`

Before the token is scoped, this is trivially true because `stacks` defaults to `Stack.all`. After a maintainer scopes a token to a single stack (the documented way to hand out a narrowly-authorized, unprivileged read-only token, e.g. fixture `here_come_the_walrus` with `stack: shipit`, `permissions: [read:stack]`), the equality breaks for the CCMenu endpoint specifically, because it never consults `stacks`.

### Impact Explanation
An attacker holding a legitimately-issued, stack-scoped, read-only `ApiClient` token (the exact kind of low-privilege token Shipit's own fixtures/documentation describe: scoped to one stack with only `read:stack`) can enumerate and read the CI/CD status - last build status, last build label/time, activity, name - of every other stack hosted by that Shipit instance, including stacks belonging to different repositories/teams the token was never meant to see. This is an authorization-scope escalation: an unprivileged, narrowly-scoped credential gains read access to state outside its granted boundary, which is the kind of stack-authorization-boundary violation explicitly in scope (the "stack a token authorizes vs. a stack it touches" binding). It does not require any GitHub credentials, session, or elevated permission beyond having the intentionally-limited token itself.

### Likelihood Explanation
High. Any deployment that hands out a stack-scoped `ApiClient` token (a normal, documented Shipit usage pattern for giving CI systems or CCTray/CCMenu clients narrow read access) is affected. Exploitation only requires calling `GET /api/stacks/:stack_id/ccmenu.xml` (or the equivalent CCMenu route) with a different stack's identifier - no special tooling needed, and the controller test suite (`test/controllers/api/ccmenu_controller_test.rb`) never exercises a stack-scoped client against a non-owned stack, so the gap is not caught by existing tests.

### Recommendation
In `Api::CCMenuController`, resolve `stack` through the inherited, scoped `stacks` collection (i.e. remove the private `#stack` override, or change it to `stacks.from_param!(params[:stack_id])`) so stack-scoped tokens cannot resolve to any stack outside their authorized `stack_id`.

### Proof of Concept
1. Create two stacks, `stack_a` and `stack_b`.
2. Create an `ApiClient` scoped to `stack_a` only: `ApiClient.create!(creator: user, name: "scoped", stack: stack_a, permissions: ["read:stack"])`.
3. Using that client's `authentication_token`, request:
   `GET /api/stacks/<owner>/<stack_b_repo>/<stack_b_env>/ccmenu.xml` with Basic Auth `token:`.
4. The response returns HTTP 200 with `stack_b`'s build/deploy status (`assert_response :ok`, `assert_payload 'name', stack_b.to_param`), even though the token's `stack_id` is `stack_a.id` and `check_permissions!` never inspects which stack is being requested.

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L22-25)
```ruby
      def show
        latest_deploy = stack.deploys_and_rollbacks.last || NoDeploy.new
        render('shipit/ccmenu/project', formats: [:xml], locals: { stack:, deploy: latest_deploy })
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
