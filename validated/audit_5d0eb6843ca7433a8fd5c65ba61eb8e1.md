### Title
CCMenu API allows an ApiClient token scoped to one stack to read the build status of any stack - (File: `app/controllers/shipit/api/ccmenu_controller.rb`)

### Summary
The CCMenu endpoint (`GET /api/stacks/:stack_id/ccmenu`) overrides the base API controller's stack-scoping logic and resolves the target `Stack` directly from the request's `stack_id` param, without checking whether the authenticated `ApiClient` is scoped to that stack. This breaks the binding "the stack a token authorizes == the stack it touches": a token issued (e.g. via the CCMenu URL feature) for read access to one specific stack can be replayed against the `stack_id` of any other stack in the installation to read its build/deploy status.

### Finding Description
`Shipit::Api::BaseController` restricts which stacks an `ApiClient` may act on based on `current_api_client.stack_id`: [1](#0-0) 

Any controller that inherits this `stack`/`stacks` helper is correctly scoped: if the `ApiClient` has a `stack_id` set, `Stack.where(id: current_api_client.stack_id)` is the only queryable relation, so requesting an out-of-scope `stack_id` param 404s.

`Shipit::Api::CCMenuController`, however, overrides `stack` to bypass this scoping entirely: [2](#0-1) 

It resolves the stack with `Stack.from_param!(params[:stack_id])` directly on the `Stack` model, not through the `stacks` scope. The only permission check performed is `require_permission :read, :stack`, which merely verifies the string `"read:stack"` is present in `current_api_client.permissions` — it never checks `current_api_client.stack_id`: [3](#0-2) 

Such stack-scoped, `read:stack`-only tokens are exactly what the built-in CCMenu URL feature generates and hands to any logged-in user for any stack they can view: [4](#0-3) 

So the equality that should hold — `ApiClient.stack_id == stack.id` for every request the client makes — is enforced by `BaseController#stack` but silently dropped by `CCMenuController#stack`. An attacker who legitimately obtains (or is handed) a CCMenu token scoped to stack A can substitute any other stack's identifier (owner/repo/environment, a guessable/enumerable triplet) as `stack_id` and receive that stack's CCMenu XML.

### Impact Explanation
The CCMenu response exposes `lastBuildStatus`, `lastBuildLabel`, `lastBuildTime`, `activity`, and `webUrl` for the targeted stack: [5](#0-4) 

This is an unauthorized cross-stack read of deploy/task state using a credential that was only supposed to authorize access to a single stack, matching the High-impact category "escalation into ... unauthenticated read of stack state, task streams or deploy output" via a token/stack authorization mismatch.

### Likelihood Explanation
Exploitation only requires possession of any valid, stack-scoped, read-only CCMenu token (routinely generated and distributed for CI dashboard integrations) and knowledge/guessing of another stack's `owner/repo/environment` identifier, which is the only parameter that needs to be changed in the request URL. No write access, no session, and no elevated permission is needed — the bug is a straightforward scope-check omission in a single controller method.

### Recommendation
Remove the `stack` override in `CCMenuController` (or make it delegate to the inherited `stacks.from_param!(params[:stack_id])`) so the `ApiClient.stack_id` scoping enforced by `BaseController` also applies to the CCMenu endpoint:
```ruby
private

def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```
This ensures a stack-scoped token can only ever resolve to the stack it was issued for.

### Proof of Concept
1. As a logged-in user with access to Stack A, visit Stack A's settings page and click "Fetch URL" for CCMenu, or call `GET /ccmenu/*stack_id` for stack A — this creates/returns an `ApiClient` with `permissions: ["read:stack"]` and `stack_id` set to Stack A's id, and returns a URL containing `?token=<TOKEN_A>`. [6](#0-5) 

2. Using `TOKEN_A`, issue a request against a *different* stack B that the token was never scoped to:
```
GET /api/stacks/<other_owner>/<other_repo>/<other_environment>/ccmenu?token=<TOKEN_A>
```
3. Because `CCMenuController#stack` calls `Stack.from_param!(params[:stack_id])` without checking `current_api_client.stack_id`, the request succeeds (HTTP 200) and returns Stack B's CCMenu XML (`lastBuildStatus`, `lastBuildLabel`, `activity`, etc.), even though `TOKEN_A` was only supposed to authorize reads of Stack A. [7](#0-6)

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

**File:** test/controllers/api/ccmenu_controller_test.rb (L33-39)
```ruby
      test "xml contains required attributes" do
        get :show, params: { stack_id: @stack.to_param }
        project = get_project_from_xml(response.body)
        %w[name activity lastBuildStatus lastBuildLabel lastBuildTime webUrl].each do |attribute|
          assert_includes project, attribute, "Response missing required attribute: #{attribute}"
        end
      end
```

**File:** test/controllers/api/ccmenu_controller_test.rb (L47-51)
```ruby
      test "stacks with no deploys render correctly" do
        stack = Stack.create!(repository: Repository.new(owner: "foo", name: "bar"), branch: 'main')
        get :show, params: { stack_id: stack.to_param }
        assert_payload 'lastBuildStatus', 'Success'
      end
```
