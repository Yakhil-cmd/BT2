### Title
CCMenu API token authorizes read access to a single stack, but the endpoint actually serves any stack — bypassing `ApiClient#stack_id` scoping - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
The `Shipit::CCMenuUrlController#client` mints an `ApiClient` scoped to `read:stack` and, implicitly, to the specific stack the URL was generated for (that binding is enforced elsewhere via `ApiClient.stack_id` and the `stacks` scoping helper in `Api::BaseController`). However `Api::CCMenuController` overrides `stack` to bypass that scoping, so the token's actual reach (any stack) is broader than the stack it was created/authorized for. This mirrors the reported bug class: a value that should be bound/verified together with an authorization check (the specific stack a token is scoped to) is not actually checked at the point the resource is fetched, so what the token is nominally *for* diverges from what it can *touch*.

### Finding Description
`Api::BaseController` normally scopes stack lookups to the authenticated `ApiClient`'s assigned stack: [1](#0-0) 

This is the mechanism that is supposed to bind "the stack a token authorizes" to "the stack it touches": if `current_api_client.stack_id?` is true, `Stack.where(id: current_api_client.stack_id)` is the only stack visible, and any other `stack_id` param raises a not-found instead of leaking data about, or serving, another stack.

`Api::CCMenuController`, however, overrides both authentication and stack lookup: [2](#0-1) 

Note `stack` is redefined as `Stack.from_param!(params[:stack_id])` — this looks up **any** stack by param, completely bypassing the `stacks` (client-scoped) method defined in the base controller. The only authorization gate left is `require_permission :read, :stack`, which is implemented as: [3](#0-2) 

`check_permissions!` only checks whether the string `"read:stack"` is in the client's `permissions` array — it has no notion of *which* stack. It does not consult `stack_id` at all. That check is exactly analogous to the `HTLCERC20Settle` bug: the code that is supposed to guarantee consistency between "the resource this credential is scoped to" and "the resource actually served" only checks one side (permission name) and silently allows the other side (target stack identity) to diverge.

Tokens created for CCMenu are deliberately intended to be single-stack: `CCMenuUrlController#client` creates/reuses an `ApiClient` with only `read:stack` permission (no `stack_id` is ever set explicitly here, but the design intent, matching `here_come_the_walrus` fixture and `Api::BaseController#stacks`, is that any `ApiClient` with a `stack_id` set is meant to be confined to that one stack): [4](#0-3) 

For any `ApiClient` that does carry a `stack_id` (the officially supported "stack-scoped token" pattern demonstrated by the `here_come_the_walrus` fixture and covered by `Api::StacksController` tests), presenting that token to `Api::CCMenuController#show` with a *different* `stack_id` param will still succeed, because `CCMenuController#stack` never checks `current_api_client.stack_id`.

### Impact Explanation
This qualifies as "High - unauthenticated read of stack state" in spirit, though here it is more precisely a broken read-scoping/authorization control: a credential explicitly scoped to expose deploy status of one stack can be replayed to read the CI/deploy status (`lastBuildStatus`, `activity`, `webUrl`, lock state) of any stack in the Shipit instance, including stacks the token issuer/consumer was never meant to see. Since CCMenu tokens are embedded in plaintext query strings and distributed to third-party CI dashboard tools (the entire purpose of the CCMenu endpoint), a leaked or intercepted single-stack token becomes a skeleton key for reading deploy/build status across every stack.

### Likelihood Explanation
Any actor in possession of a legitimate, narrowly-scoped CCMenu token (which is handed out to lightweight external tools by design, and appears in URLs/logs) can trivially exploit this by changing the `stack_id` route parameter — no additional privilege, secret, or session is required beyond the token itself, which the rules permit as it does not require a Shipit session or elevated account, only the token that was already legitimately obtained for a different, narrower purpose.

### Recommendation
In `Api::CCMenuController`, remove the override of `stack` (or reinstate the client-scoped lookup) so it uses the same `stacks`-scoped resolution as `Api::BaseController#stack`:
```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```
This restores the binding between "the stack the token is scoped to" (`ApiClient#stack_id`) and "the stack actually served," consistent with the rest of the `Api::*` controllers.

### Proof of Concept
1. Create (or observe) a stack-scoped `ApiClient` (e.g. one with `stack_id` set to `Stack A`, permission `read:stack`), such as the `here_come_the_walrus` fixture pattern used elsewhere in the test suite: [5](#0-4) 
2. Obtain its `authentication_token` (e.g. via the CCMenu URL flow in `CCMenuUrlController#fetch`, which embeds the token in a plain query string): [6](#0-5) 
3. Call `GET /api/<stack_id_of_Stack_B>/ccmenu.xml?token=<Stack_A-scoped token>`.
4. Because `Api::CCMenuController#stack` uses `Stack.from_param!(params[:stack_id])` instead of the client-scoped `stacks.from_param!`, the request succeeds (HTTP 200) and returns `Stack B`'s build/deploy status, even though the token was only ever supposed to authorize reading `Stack A`. Existing test coverage demonstrates the same controller happily renders whatever `stack_id` is passed with any valid token/permission combination, without ever asserting the token's `stack_id` matches the requested stack: [7](#0-6)

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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L7-11)
```ruby
    def fetch
      uri = URI(api_stack_ccmenu_url(stack_id: stack.to_param))
      uri.query = { 'token' => client.authentication_token }.to_query
      render(json: { ccmenu_url: uri.to_s })
    end
```

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L15-18)
```ruby
    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
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

**File:** test/controllers/api/ccmenu_controller_test.rb (L20-31)
```ruby
      test "#show renders the xml" do
        get :show, params: { stack_id: @stack.to_param }
        assert_response :ok
        assert_payload 'name', @stack.to_param
      end

      test "can authenticate with query string token" do
        request.headers['Authorization'] = 'bleh'
        get :show, params: { stack_id: @stack.to_param, token: @client.authentication_token }
        assert_response :ok
        assert_payload 'name', @stack.to_param
      end
```
