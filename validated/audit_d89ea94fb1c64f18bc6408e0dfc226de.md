## Finding: CCMenu API endpoint bypasses `ApiClient` stack-scoping

### Title
CCMenu endpoint lets a stack-scoped `ApiClient` token read status of any stack, bypassing token stack scoping - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
The reported bug class is a trust binding that is enforced in one code path but silently dropped in another equivalent path (`STADIUM_ADDRESS` immutably trusted at distribution time but never revisited when conditions change). The Shipit analog is the binding between "the stack an `ApiClient` is authorized for" and "the stack a controller action actually operates on." This binding is correctly enforced in `Shipit::Api::BaseController#stack`, but `Shipit::Api::CCMenuController` reimplements `#stack` without the scoping check, breaking the equality `token.authorized_stack == stack_being_read`.

### Finding Description
`Shipit::Api::BaseController` defines the canonical, scope-respecting resolver used by every other API controller: [1](#0-0) 

`stacks` restricts the queryable set to `current_api_client.stack_id` when the client is scoped to one stack, and `stack` resolves `params[:stack_id]` only within that restricted relation.

`Shipit::Api::CCMenuController`, however, overrides `stack` to bypass this relation entirely and resolve directly against the unrestricted `Stack` model: [2](#0-1) 

The controller's only authorization check is `require_permission :read, :stack`, which merely verifies the token's `permissions` array contains `read:stack` — it never checks that `params[:stack_id]` matches the client's own `stack_id`: [3](#0-2) [4](#0-3) 

Compare with `ApiClient#stack_id` intent, exercised and enforced elsewhere (e.g. `StacksController#index`), where a stack-scoped client is confirmed to only see its own stack: [5](#0-4) 

No such enforcement exists in `CCMenuController#show`, which renders build status directly from the unscoped `stack`: [6](#0-5) 

The route accepts an arbitrary `stack_id` segment for any stack in the installation: [7](#0-6) 

### Impact Explanation
An `ApiClient` deliberately created with `stack: <specific stack>` (the documented mechanism for handing out narrowly-scoped tokens, e.g. to a CI badge/status integration) can supply any other stack's `stack_id` in the URL and retrieve that stack's deploy activity, last build status/label, last build time, and web URL — data the token issuer never intended to expose to that integration. This is a cross-stack authorization bypass: the equality `token.stack_id == requested_stack` that holds everywhere else in the API is broken specifically in `CCMenuController`, allowing an unauthenticated-relative-to-that-stack read of deploy/task state for stacks outside the token's authorized scope.

### Likelihood Explanation
Any consumer holding a legitimately-issued, single-stack-scoped `ApiClient` token (a normal, low-privilege credential meant only for CCTray/CI badge integration) can trivially trigger this by changing the `stack_id` path segment of the `ccmenu` URL. No additional access, secrets, or write permission is required beyond the token already granted for one stack.

### Recommendation
Have `CCMenuController` reuse the inherited, scope-respecting `stack`/`stacks` resolvers from `BaseController` instead of querying `Stack.from_param!` directly, so that a stack-scoped token can only resolve its own stack, consistent with every other API controller.

### Proof of Concept
1. Admin issues a stack-scoped `ApiClient` token `T` with `stack: "org/repoA/production"` and permission `read:stack` (e.g., fixture `here_come_the_walrus`).
2. Attacker (holder of `T`, e.g. a CI system for repoA) sends:
   `GET /api/stacks/org/repoB/staging/ccmenu?token=T`
3. `authenticate_api_client` in `CCMenuController` authenticates `T` successfully via `ApiClient.authenticate(params[:token])`.
4. `require_permission :read, :stack` passes because `T.permissions` includes `read:stack` (scope is not stack-specific).
5. `stack` resolves `Stack.from_param!("org/repoB/staging")` with no scoping check, returning `repoB`'s stack even though `T.stack_id` points to `repoA`.
6. The XML response discloses `repoB`'s last build status/label/time/webUrl to a token never authorized for `repoB`.

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L5-6)
```ruby
    class CCMenuController < BaseController
      require_permission :read, :stack
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L22-25)
```ruby
      def show
        latest_deploy = stack.deploys_and_rollbacks.last || NoDeploy.new
        render('shipit/ccmenu/project', formats: [:xml], locals: { stack:, deploy: latest_deploy })
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

**File:** config/routes.rb (L27-29)
```ruby
    scope '/stacks/*stack_id', stack_id: stack_id_format, as: :stack do
      get '/ccmenu' => 'ccmenu#show', as: :ccmenu
      resource :lock, only: %i[create update destroy]
```
