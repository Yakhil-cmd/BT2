### Title
Cross-stack information disclosure: `Api::CCMenuController` uses an unscoped `Stack` lookup, bypassing the `ApiClient`'s stack authorization - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Api::CCMenuController#stack` resolves the target stack directly from `Stack.from_param!(params[:stack_id])`, instead of going through `Api::BaseController#stacks`/`#stack`, which is the mechanism that enforces that a stack-scoped `ApiClient` can only touch the single stack it was created for. This breaks the binding: `token.authorized_stack == stack_the_controller_acts_on`.

### Finding Description
`Api::BaseController` defines the authorization-aware accessor: [1](#0-0) 

`stacks` is filtered to `current_api_client.stack_id` when the client is scoped to a specific stack, and `stack` is derived from that filtered relation. `CCMenuController`, however, overrides `stack` to bypass this scoping entirely: [2](#0-1) 

`require_permission :read, :stack` only checks that the `ApiClient` has the `read:stack` permission string in its `permissions` array via `ApiClient#check_permissions!`: [3](#0-2) 

It never checks that the requested `stack_id` matches the client's own `stack_id`. Elsewhere in the same controller family, this scoping matters and is tested: an `ApiClient` created with `stack: shipit` in fixtures is expected to only see that one stack. [4](#0-3) [5](#0-4) 

But `CCMenuController#show` calls `stack.deploys_and_rollbacks.last`, where `stack` is the unscoped lookup, so any valid token — even one deliberately scoped to a single stack — can fetch CCTray/CI status for any stack in the installation by simply changing the `stack_id` route parameter: [6](#0-5) 

### Impact Explanation
This meets the High-impact bar: "unauthenticated read of stack state, task streams or deploy output" in the sense that a token authenticated for one stack achieves unauthorized read access to another stack's build/deploy status (branch, last build label/SHA, activity, lock state, web URL) that its permission grant should not cover. It is a cross-repository/cross-stack read escalation, directly analogous to the FSD `_addTribute` vs `_addGovernanceTribute` bug class: the code path that authorizes ("does this ApiClient's stack_id match?") is never invoked, even though the analogous code path is (`Api::BaseController#stack`/`#stacks`).

### Likelihood Explanation
Likelihood is high: exploitation only requires possessing any valid, unprivileged `ApiClient` token scoped to a single stack (e.g., created via `CCMenuUrlController#client`, which itself creates `read:stack`-only, stack-scoped clients for CCMenu use) and requesting `/api/<other_stack_id>/ccmenu?token=...` instead of the stack it was minted for. No elevated privileges, session, or additional secrets are needed beyond the token the client already legitimately holds for its own stack.

### Recommendation
Change `CCMenuController#stack` to reuse the authorization-aware `stacks`/`stack` scoping from `Api::BaseController` (i.e., remove the private `stack` override and rely on `stacks.from_param!(params[:stack_id])`), so that a stack-scoped `ApiClient` cannot resolve stacks outside its `stack_id`.

### Proof of Concept
1. Using `CCMenuUrlController#client`/fixtures, obtain (or create) an `ApiClient` scoped to `stack_id = A` with only `read:stack` permission (e.g., `here_come_the_walrus` in fixtures, scoped to `shipit_stacks(:shipit)`).
2. Get its `authentication_token` (as done in `CCMenuUrlController#fetch`). [7](#0-6) 
3. Issue `GET /api/<stack_B>/ccmenu?token=<tokenA>` where `stack_B != A`.
4. `authenticate_api_client` in `CCMenuController` authenticates the token successfully (`ApiClient.authenticate(params[:token])`), and `require_permission :read, :stack` passes since `read:stack` is present.
5. `stack` resolves `Stack.from_param!(params[:stack_id])` directly against `stack_B`, unscoped by the client's own `stack_id`, and returns `stack_B`'s deploy/build status in the response XML — data the token was never authorized to access. [8](#0-7)

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L22-36)
```ruby
      def show
        latest_deploy = stack.deploys_and_rollbacks.last || NoDeploy.new
        render('shipit/ccmenu/project', formats: [:xml], locals: { stack:, deploy: latest_deploy })
      end

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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L6-18)
```ruby
  class CCMenuUrlController < ShipitController
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
