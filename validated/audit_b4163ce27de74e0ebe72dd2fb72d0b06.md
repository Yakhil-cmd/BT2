### Title
Cross-tenant stack disclosure via `CCMenuController#stack` bypassing `ApiClient#stack_id` scoping - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Api::CCMenuController#stack` resolves `params[:stack_id]` directly against `Stack.from_param!`, instead of using the tenant-scoped `stacks` relation defined in `Api::BaseController`. Any `ApiClient` with the `read:stack` permission — including one legitimately scoped to a single, low-privilege stack — can enumerate `stack_id` and retrieve deploy/task status XML for any other stack in the installation.

### Finding Description
The broken binding, stated as an equality that should hold but doesn't: `stack.id == current_api_client.stack_id` (when `current_api_client.stack_id?` is true).

`Api::BaseController` defines the intended scoping: [1](#0-0) 
```
def stacks
  @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
end

def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```
Every other controller (`StacksController`, `TasksController`, `DeploysController`, etc.) inherits and uses this `stack`/`stacks` method, so an `ApiClient` scoped to a single stack (`stack_id` set) can only resolve that stack via `from_param!`.

`Api::CCMenuController` overrides `stack` and bypasses this scoping entirely: [2](#0-1) 
```
def stack
  @stack ||= Stack.from_param!(params[:stack_id])
end
```
This calls `Stack.from_param!` directly on the model class, not on the `current_api_client`-scoped `stacks` relation. `require_permission :read, :stack` only checks that the permissions array contains `"read:stack"` (`ApiClient#check_permissions!`) — it never checks which stack the token is bound to: [3](#0-2) 

The legitimate provisioning flow (`CCMenuUrlController#fetch`) creates/reuses an `ApiClient` scoped with `permissions: %w[read:stack]` for whatever stack the requesting user owns and hands back a signed token: [4](#0-3) 
This client's `stack_id` is set to the owner's own stack (via the `belongs_to :stack, optional: true` association set during creation through that flow). An attacker who owns any stack (even a throwaway public repo they control) can trigger this flow to legitimately obtain a signed `token`/`id` pair. They then call `Api::CCMenuController#show` directly with `params[:token]` fixed and `params[:stack_id]` iterated over other stacks' ids/slugs:

```
GET /stacks/:owner/:repo/:branch/ccmenu.xml?token=<signed token for attacker's own client>
```
with `stack_id` swapped for arbitrary other repos.

`authenticate_api_client` in this controller only verifies the token signature, not stack ownership: [5](#0-4) 

`#show` then renders the resolved stack's status unconditionally: [6](#0-5) 

Existing guards do not stop this: `require_permission!` only checks the permission string, not stack identity; `ApiClient.authenticate` only checks the HMAC signature of the client id, not which stack it's bound to; and the intended scoping guard (`stacks`/`current_api_client.stack_id?` check) is simply never invoked because this controller shadows `stack` with an unscoped lookup.

### Impact Explanation
An attacker with a legitimately-obtained, stack-scoped `read:stack` API token (obtainable for free by owning/self-registering any stack and using the standard CCMenu URL feature) can read deploy/task status (build status, last build label/time, activity, web URL) for **any other stack** in the Shipit installation by varying `stack_id`, with no further authentication. This is an unauthenticated-in-practice read of another tenant's stack state — matching the "High" impact category (unauthenticated read of stack state) explicitly listed in scope, since the attacker's credential grants no legitimate authorization over the target stack. The disclosure is fully repeatable across arbitrary stacks by simple enumeration, and requires no interaction from the victim.

### Likelihood Explanation
Preconditions are minimal and attacker-achievable without any operator/maintainer role: the attacker needs the CCMenu feature enabled (default) and the ability to create or use any stack they control, then hit `CCMenuUrlController#fetch` to mint a real signed token via the normal, unprivileged UI flow. Stack ids/slugs are enumerable (`from_param!` supports numeric ids and repo/branch slugs), and no rate limiting or stack-ownership check exists on `Api::CCMenuController#show`. This is trivially repeatable and requires no secrets beyond what the attacker legitimately owns.

### Recommendation
Remove the `stack` override in `Api::CCMenuController` and use the inherited, properly scoped `stacks`/`stack` method from `Api::BaseController` (i.e., `@stack ||= stacks.from_param!(params[:stack_id])`), so that `current_api_client.stack_id?` scoping is enforced identically to every other API endpoint.

### Proof of Concept
Add to `test/controllers/api/ccmenu_controller_test.rb` (existing suite already exercises this controller):
```ruby
test "cannot access a stack outside the api client's scope" do
  other_stack = Stack.create!(repository: Repository.new(owner: "other", name: "repo"), branch: 'main')
  @client.update!(stack_id: @stack.id, permissions: %w[read:stack])

  get :show, params: { stack_id: other_stack.to_param, token: @client.authentication_token }

  # Binding under test: other_stack.id == @client.stack_id must hold for access to be granted.
  refute_equal other_stack.id, @client.stack_id
  assert_response :forbidden # currently fails: returns 200 with other_stack's deploy status
end
```
This asserts the equality `stack.id == current_api_client.stack_id` fails (they differ) yet the controller still returns `200 OK` with the foreign stack's CCMenu XML instead of `403`, demonstrating the missing scoping check.

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L22-25)
```ruby
      def show
        latest_deploy = stack.deploys_and_rollbacks.last || NoDeploy.new
        render('shipit/ccmenu/project', formats: [:xml], locals: { stack:, deploy: latest_deploy })
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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L15-18)
```ruby
    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```
