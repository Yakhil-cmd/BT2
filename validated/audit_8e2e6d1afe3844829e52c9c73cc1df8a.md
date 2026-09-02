### Title
CCMenu API endpoint bypasses per-stack ApiClient scoping, letting a stack-scoped token read the status of any stack - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Shipit::Api::CCMenuController` overrides the `stack` lookup method to resolve the stack directly from `params[:stack_id]` instead of going through the token-scoped `stacks` collection used by every other API controller. This breaks the binding "a stack a token authorises versus a stack it touches": an `ApiClient` created with a `stack_id` (i.e. explicitly restricted to one stack) can still be used to fetch CCMenu status for any other stack in the installation.

### Finding Description
`Shipit::Api::BaseController` enforces stack scoping centrally: [1](#0-0) 

```ruby
def stacks
  @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
end

def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```

Any controller that relies on the inherited `stack` method is automatically limited to the stack(s) its `ApiClient` is authorized for. `Shipit::Api::CCMenuController`, however, redefines `stack` to bypass this scoping entirely: [2](#0-1) 

```ruby
def stack
  @stack ||= Stack.from_param!(params[:stack_id])
end

def authenticate_api_client
  @current_api_client = ApiClient.authenticate(params[:token])
  super unless @current_api_client
end
```

`ApiClient` records can be scoped to a single stack (`belongs_to :stack, optional: true`, see `Shipit::ApiClient`), which is exactly what the "CCMenu URL" feature does: `CcmenuUrlController#fetch` mints a read-only `ApiClient` scoped to the current stack and hands the caller a token+URL pair for that one stack. The equality that should hold is:

`current_api_client.stack_id (the stack the token authorises) == stack (the stack the request touches)`

but `CCMenuController#stack` never checks this — it accepts any `params[:stack_id]` and loads it via the unscoped `Stack.from_param!`. `require_permission :read, :stack` only checks that the `read:stack` permission bit is present in `current_api_client.permissions`; it does not verify which stack that permission applies to (`Shipit::ApiClient#check_permissions!` only compares permission strings, not stack identity).

### Impact Explanation
An attacker who obtains (or is legitimately issued) a stack-scoped CCMenu token — e.g. by viewing the "CCMenu URL" of one stack they have access to, since that URL embeds a bearer token in the query string and is often pasted into third-party CI dashboard tools — can reuse that same token against `GET /api/:other_stack_id/cctray.xml?token=...` to read build/deploy status (`name`, `activity`, `lastBuildStatus`, `lastBuildLabel`, `lastBuildTime`, `webUrl`) for every other stack in the Shipit installation, including private/production stacks the token was never meant to see. This is an unauthorized cross-stack read of stack state, matching the High-severity category of "unauthenticated/unauthorized read of stack state ... through a mis-scoped credential."

### Likelihood Explanation
Likelihood is Medium-High: no privileged access is required beyond possessing any valid stack-scoped CCMenu token (these tokens are designed to be shared with external CI-status tools and are not treated as highly secret), and the only additional step is substituting a different `stack_id` in the URL path, which is trivial and requires no additional credentials or team membership.

### Recommendation
Make `Shipit::Api::CCMenuController#stack` reuse the scoped `stacks` collection from `BaseController` (i.e. `stacks.from_param!(params[:stack_id])`) instead of `Stack.from_param!(params[:stack_id])`, so that a stack-scoped `ApiClient` can only resolve the stack(s) it was actually authorized for. Add a regression test asserting that a token scoped to stack A receives a 404/`RecordNotFound` when `stack_id` for stack B is supplied to `Api::CCMenuController#show`.

### Proof of Concept
1. As an authenticated Shipit user, visit stack A's page and trigger the "CCMenu URL" fetch action, which creates a read-only `ApiClient` scoped to stack A (`stack_id = A.id`) and returns a URL like `https://shipit.example.com/api/A/cctray.xml?token=<TOKEN>`. [3](#0-2) 
2. Take `<TOKEN>` and issue: `GET https://shipit.example.com/api/B/cctray.xml?token=<TOKEN>` for an arbitrary stack B that the token was never scoped to.
3. Because `Api::CCMenuController#stack` uses `Stack.from_param!(params[:stack_id])` directly rather than the token-scoped `stacks` relation, the request succeeds with `200 OK` and returns stack B's CCMenu XML (name, activity, last build status/label/time, web URL), even though `current_api_client.stack_id` is A, not B — demonstrated by contrast with `Api::BaseController#stack`, which every other authenticated API controller correctly uses: [1](#0-0)

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

**File:** test/controllers/ccmenu_controller_test.rb (L21-33)
```ruby
    test ":fetch creates a read only api client" do
      assert_difference 'ApiClient.count' do
        get :fetch, params: { stack_id: @stack.to_param }
      end
    end

    test ":fetch url includes api token on query string" do
      get :fetch, params: { stack_id: @stack.to_param }
      data = JSON.parse(response.body)
      client = ApiClient.last
      query = Rack::Utils.parse_nested_query(URI(data['ccmenu_url']).query)
      assert_equal client.authentication_token, query['token']
    end
```
