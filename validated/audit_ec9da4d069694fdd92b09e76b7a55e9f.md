### Title
CCMenu API endpoint bypasses ApiClient stack-scoping, allowing a stack-scoped token to read the deploy status of any stack - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Shipit::Api::CCMenuController` overrides the `stack` lookup method inherited from `Shipit::Api::BaseController` with a version that resolves the stack directly via `Stack.from_param!(params[:stack_id])` instead of the scoped `stacks.from_param!(params[:stack_id])`. This breaks the binding between the stack(s) an `ApiClient` token is authorized for and the stack whose data is actually returned, analogous to the deposit-front-running bug class where the value verified (the withdrawal credential attached to the first, small deposit) is not the value ultimately bound (the credential used for the full deposit).

### Finding Description
`ApiClient` tokens can be scoped to a single stack via `stack_id`, and `Shipit::Api::BaseController` enforces that scoping through the `stacks`/`stack` helpers: [1](#0-0) 

```ruby
def stacks
  @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
end

def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```

This is the equality binding that should hold for every API endpoint: `stack_rendered_by_controller == stack authorized by ApiClient.stack_id (when stack-scoped)`.

`Shipit::Api::CCMenuController`, however, defines its own `stack` method that ignores the `stacks` scoping entirely: [2](#0-1) 

```ruby
def show
  latest_deploy = stack.deploys_and_rollbacks.last || NoDeploy.new
  render('shipit/ccmenu/project', formats: [:xml], locals: { stack:, deploy: latest_deploy })
end

private

def stack
  @stack ||= Stack.from_param!(params[:stack_id])
end
```

`require_permission :read, :stack` only calls `current_api_client.check_permissions!(:read, :stack)`, which checks the client's `permissions` array (`app/models/shipit/api_client.rb`, `check_permissions!`) but never checks that the requested `stack_id` matches `current_api_client.stack_id`: [3](#0-2) 

```ruby
def check_permissions!(operation, scope)
  required_permission = "#{operation}:#{scope}"
  unless permissions.include?(required_permission)
    raise InsufficientPermission, "This operation requires the `#{required_permission}` permission"
  end

  true
end
```

Because `CCMenuController#stack` resolves `params[:stack_id]` against `Stack.from_param!` (all stacks) rather than `stacks.from_param!` (the client's authorized scope), the `Before/After` state is:

- Before request: `ApiClient#stack_id` == Stack A (the only stack the token is meant to read).
- After request with `stack_id=StackB`: the controller renders Stack B's `deploys_and_rollbacks.last` (last build status, label, activity, web URL) even though the token was never authorized for Stack B.

The equality `stack authorized-by-token == stack read-by-controller` is broken specifically in this controller, even though the sibling `Shipit::Api::StacksController` and other API controllers correctly use the inherited `stack`/`stacks` helpers from `BaseController`.

### Impact Explanation
This matches the "High" impact category: *unauthenticated read of stack state, task streams or deploy output* relative to what the presented `ApiClient` token authorizes. A token holder who is only supposed to see one stack's CI/build status can enumerate `stack_id` values and read the last build status/label/time/URL of every other stack configured in the Shipit instance, leaking information about deploy activity and repository/environment names across stacks the client was never granted access to.

### Likelihood Explanation
Likelihood is high for any deployment using stack-scoped `ApiClient` tokens (a supported, documented feature — e.g., the auto-created CCMenu client in `app/controllers/shipit/ccmenu_url_controller.rb`, which explicitly creates a `read:stack`-scoped client tied to one stack). Any holder of such a token — which is explicitly meant to be handed out to less-trusted third-party CI-status tools — can simply change the `stack_id` route segment to access other stacks' data. No additional privilege, signature, or session is required beyond the token itself, which is the credential the feature is designed to hand out with limited scope.

### Recommendation
Remove the overriding `stack` method in `Shipit::Api::CCMenuController` (or reimplement it using the inherited `stacks.from_param!(params[:stack_id])`) so the stack lookup is always constrained by `current_api_client.stack_id` scoping, consistent with `Shipit::Api::BaseController`. Add regression tests asserting that a stack-scoped `ApiClient` token receives a 404/403 when requesting `stack_id` values other than the one it is scoped to.

### Proof of Concept
1. Create (or use the auto-created) `ApiClient` scoped to Stack A with `permissions: ['read:stack']`, e.g. via `Shipit::CCMenuUrlController#fetch`, which creates: `ApiClient.create_with(permissions: %w[read:stack]).find_or_create_by!(creator: current_user, name: 'CCMenu Client')` bound to Stack A's `ccmenu_url`. [4](#0-3) 
2. Take that client's `authentication_token` (exposed via the generated `ccmenu_url` query string `token` param).
3. Send `GET /api/<stack-A-owner>/<stack-A-repo>/<env-A>/ccmenu.xml?token=<token>` — succeeds as intended.
4. Send `GET /api/<other-owner>/<other-repo>/<other-env>/ccmenu.xml?token=<token>` for a completely unrelated Stack B.
5. Because `CCMenuController#stack` calls `Stack.from_param!(params[:stack_id])` instead of the scoped `stacks.from_param!`, the request succeeds and returns Stack B's build status/name/activity, even though the token's `ApiClient#stack_id` is Stack A's id.

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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L14-18)
```ruby

    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```
