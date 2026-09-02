## Title
CCMenu API endpoint bypasses `ApiClient#stack_id` scoping, allowing a stack-scoped token to read any stack's build status - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Shipit::Api::CCMenuController#stack` resolves the target stack with `Stack.from_param!(params[:stack_id])` instead of using the `stacks` scoping helper (`stacks.from_param!`) that every other API controller relies on. Because `ApiClient` tokens can be scoped to a single stack via `stack_id`, this bypass lets any valid token — even one explicitly restricted to a single stack — read the CI/CD status (last deploy/rollback outcome) of every stack in the Shipit instance.

### Finding Description
`ApiClient` records can carry an optional `stack_id` that is meant to restrict what the token can see: `BaseController#stacks` only exposes `Stack.where(id: current_api_client.stack_id)` when the client is scoped [1](#0-0) , and every stack-touching action is expected to look the target stack up through that scoped relation, e.g. `StacksController#stack` uses `stacks.from_param!(params[:id])` [2](#0-1) .

`CCMenuController`, however, defines its own `stack` method that resolves the stack directly against the unscoped `Stack` model: [3](#0-2) 

`require_permission :read, :stack` only checks that the token's `permissions` array contains `read:stack` [4](#0-3) ; it never checks whether the requested `stack_id` param matches `current_api_client.stack_id`. That equality — `current_api_client.stack_id == requested stack.id` — is the binding the `stacks` scoping helper is meant to enforce, and `CCMenuController` never applies it.

The fixture `here_come_the_walrus` demonstrates the intended restriction: it is scoped to the `shipit` stack only and holds `read:stack` [5](#0-4) ; the existing test suite confirms it is meant to "only see that one stack" via `StacksController#index` [6](#0-5) . Because `CCMenuController` doesn't reuse that scoping, the same token can be used against `/api/*/stacks/<any-other-stack>/ccmenu.xml` to read that other stack's status.

### Impact Explanation
This is an unauthenticated-scope read of stack state: an attacker who legitimately holds any token restricted to a single, low-sensitivity stack (e.g. a CCMenu client auto-created and exposed via `CCMenuUrlController#fetch` for any user who can view a single stack, see `app/controllers/shipit/ccmenu_url_controller.rb`) can enumerate and read the deploy/rollback status of every other stack managed by that Shipit instance, including private/internal ones the attacker was never granted access to. This matches the High-impact bucket "unauthenticated read of stack state, task streams or deploy output."

### Likelihood Explanation
Likelihood is high for anyone who already possesses a stack-scoped read-only token: `CCMenuUrlController#fetch` creates a `read:stack`-only, stack-scoped `ApiClient` for the current user on demand (`app/controllers/shipit/ccmenu_url_controller.rb`, lines 15-18), so many ordinary users of the tool already hold such a token intended for use with a single stack. No special privilege beyond viewing one stack is needed to obtain and then misuse this token against `CCMenuController#show` with a different `stack_id`.

### Recommendation
Change `CCMenuController#stack` to reuse the same scoping used elsewhere, e.g. `stacks.from_param!(params[:stack_id])`, so the `current_api_client.stack_id` restriction is enforced consistently across all API endpoints, and add a regression test asserting that a stack-scoped client cannot fetch CCMenu data for a stack other than the one it is scoped to.

### Proof of Concept
1. As a Shipit user with access only to `stack-A`, visit `stack-A`'s overview page, which calls `CCMenuUrlController#fetch` and creates (or reuses) a `read:stack`-only `ApiClient` scoped to `stack-A` (`app/controllers/shipit/ccmenu_url_controller.rb`).
2. Extract that client's `authentication_token`.
3. Issue `GET /api/<other-stack-owner>/<other-stack-name>/ccmenu.xml?token=<token>` for `stack-B`, a stack the attacker was never granted access to.
4. Because `CCMenuController#stack` calls `Stack.from_param!(params[:stack_id])` directly rather than `stacks.from_param!`, the request succeeds and returns `stack-B`'s latest deploy/rollback status, bypassing the token's intended single-stack scope (as confirmed by the working `authenticate!`/`token=`-based test pattern in `test/controllers/api/ccmenu_controller_test.rb`, lines 26-31, which never exercises the scoping restriction).

### Citations

**File:** app/controllers/shipit/api/base_controller.rb (L74-76)
```ruby
      def stacks
        @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
      end
```

**File:** app/controllers/shipit/api/stacks_controller.rb (L87-89)
```ruby
      def stack
        @stack ||= stacks.from_param!(params[:id])
      end
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L27-31)
```ruby
      private

      def stack
        @stack ||= Stack.from_param!(params[:stack_id])
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

**File:** test/fixtures/shipit/api_clients.yml (L12-17)
```yaml
here_come_the_walrus:
  name: Here Come The Walrus
  creator: walrus
  stack: shipit
  permissions:
    - 'read:stack'
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
