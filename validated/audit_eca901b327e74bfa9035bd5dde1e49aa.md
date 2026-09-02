## Title
Stack-scoped API tokens bypass their authorized `stack_id` in `CCMenuController` - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Shipit::ApiClient` can be scoped to a single stack via its `stack_id` column, and every other API controller enforces that scope by resolving stacks through `BaseController#stacks`/`#stack`. `Api::CCMenuController` overrides `#stack` to resolve the stack directly from `params[:stack_id]` without ever consulting `current_api_client.stack_id`, so a token that is only authorized for stack A can be used to read the build/deploy status of any other stack.

### Finding Description
`BaseController` centralizes the binding "token's authorized stack == stack being accessed": [1](#0-0) 

```ruby
def stacks
  @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
end

def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```

Any controller relying on the inherited `stack` method (e.g. `Api::DeploysController`, `Api::StacksController`) is protected: if the authenticated `ApiClient` has a non-nil `stack_id`, `Stack.from_param!` will only find records within that scope, and `find_by!`-style resolution raises `RecordNotFound` for any other stack.

`Api::CCMenuController`, however, redefines `stack` and never joins it back to the `stacks` scope: [2](#0-1) 

```ruby
def stack
  @stack ||= Stack.from_param!(params[:stack_id])
end

def authenticate_api_client
  @current_api_client = ApiClient.authenticate(params[:token])
  super unless @current_api_client
end
```

It only enforces the permission string via `require_permission :read, :stack`, which is checked in `ApiClient#check_permissions!` — a pure membership test on the `permissions` array with no relation to `stack_id`: [3](#0-2) 

So the equality that should hold — `current_api_client.stack_id == stack.id (when stack_id present)` — is checked everywhere except this controller. Any `ApiClient` with `read:stack` permission, whether it is scoped to a specific stack (`stack_id` set) or the token is exposed through the CCMenu URL feature, can pass an arbitrary `stack_id`/`token` combination and read data for a stack outside its authorized scope. The fixture `here_come_the_walrus` demonstrates exactly this kind of scoped client (`stack: shipit`, `permissions: [read:stack]`): [4](#0-3) 

### Impact Explanation
This breaks the "a stack a token authorises versus a stack it touches" binding called out as in-scope. A caller holding any valid stack-scoped `ApiClient` token (Basic-Auth header or `?token=`) can enumerate/read CI/deploy status (`lastBuildStatus`, `lastBuildLabel`, `activity`, lock state, etc., rendered by `shipit/ccmenu/project`) for stacks/repositories it was never granted access to — an unauthorized cross-stack read of stack/deploy state, matching the High-severity category "unauthenticated read of stack state, task streams or deploy output" (here, out-of-scope read via a token that authenticates but is not authorized for that stack).

### Likelihood Explanation
No privileged access is required beyond possessing any existing `read:stack`-permissioned `ApiClient` token — including ones legitimately minted and scoped to a single stack by `CCMenuUrlController` for CI dashboard integration: [5](#0-4) 

The attack is a single unauthenticated-parameter GET request; it requires no signature forgery, no session, and no elevated privilege — only knowledge of another stack's `stack_id` route parameter, which is derivable from repository owner/name/environment/branch and is not secret.

### Recommendation
Make `Api::CCMenuController#stack` resolve through the same authorization-scoped relation as the rest of the API, e.g. `stacks.from_param!(params[:stack_id])` (inherited from `BaseController`), instead of `Stack.from_param!(params[:stack_id])` directly, so a stack-scoped token can never resolve a stack outside `current_api_client.stack_id`.

### Proof of Concept
1. As an authorized user, use `CCMenuUrlController#fetch` (or any admin flow) to obtain a `read:stack`-permissioned `ApiClient` token scoped to stack `owner/repo-a/production` (`stack_id` set to that stack's id).
2. Send `GET /api/owner/repo-b/production/ccmenu.xml?token=<token>` (a different stack the client is not scoped to).
3. `authenticate_api_client` successfully resolves `current_api_client` via `ApiClient.authenticate(params[:token])`; `require_permission :read, :stack` passes because the client's `permissions` array contains `read:stack`; `stack` resolves `repo-b/production` directly via `Stack.from_param!`, bypassing the `stack_id` restriction, and the controller renders `repo-b`'s deploy/build status to the caller.

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

**File:** test/fixtures/shipit/api_clients.yml (L12-17)
```yaml
here_come_the_walrus:
  name: Here Come The Walrus
  creator: walrus
  stack: shipit
  permissions:
    - 'read:stack'
```

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L15-18)
```ruby
    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```
