### Title
CCMenu API token is not scoped to the stack it was minted for, allowing read access to any stack's build status - ([File: app/controllers/shipit/ccmenu_url_controller.rb])

### Summary
`CCMenuUrlController#client` mints an `ApiClient` with `read:stack` permission but never binds it to the `Stack` for which the URL was generated. `CCMenuController` then trusts that token to read whatever `stack_id` is supplied in the request, not the stack the token was created for. This breaks the intended binding "the stack a token authorises" == "the stack it touches."

### Finding Description
`CCMenuUrlController#fetch` builds a CCMenu URL for a specific stack and mints (or reuses) a per-user `ApiClient` to embed as `token` in that URL: [1](#0-0) 

```rb
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

def stack
  @stack ||= Stack.from_param!(params[:stack_id])
end
```

Crucially, `find_or_create_by!` is keyed only by `creator` and `name`, and no `stack:` attribute is ever passed to `create_with`/`find_or_create_by!`. `ApiClient#stack` is an optional `belongs_to`, so this client is created with `stack_id: nil`, i.e. it is a global, unscoped, read-only token that is reused for every stack the user ever generates a CCMenu URL for: [2](#0-1) 

On the consuming side, `CCMenuController` authenticates purely via this per-user, stack-agnostic token (bypassing session/team authentication entirely, by design, so external CI dashboards can poll it), then resolves the target stack directly from the request parameter instead of scoping through the authorized stack list: [3](#0-2) 

```rb
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

For comparison, the regular API `BaseController` does scope `stack` resolution to the client's authorized stack via `current_api_client.stack_id?`: [4](#0-3) 

`CCMenuController` overrides `stack` and drops this scoping entirely, and because the underlying `ApiClient` was never bound to a stack in the first place (`stack_id` is always `nil` for CCMenu clients), there is no server-side enforcement tying the token to the stack it was minted for.

**Binding broken:** `stack a token authorises` (the stack for which the URL/token was generated and intended, e.g. `stack A`) != `stack a token actually touches` (any `stack_id` param an unauthenticated bearer of the token supplies, e.g. `stack B`, `stack C`, ...).

Before the attacker's action: user with access to Stack A calls `GET /ccmenu_url?stack_id=A`, receiving a URL containing `token=T` intended to expose only Stack A's status to unauthenticated pollers (e.g. embedded in a public CI dashboard widget).
After the attacker's action: anyone in possession of `T` (which is meant to be shared outside of any Shipit session, that being the entire purpose of a CCMenu URL) can call `GET /api/stacks/:any_stack_id/ccmenu?token=T` for any stack in the Shipit instance and receive its latest deploy/build status, because `T` carries no stack restriction.

### Impact Explanation
This is an unauthenticated read of stack state, matching the High-impact bucket: "unauthenticated read of stack state, task streams or deploy output." CCMenu tokens are specifically designed to be shared with tools outside of a Shipit session (that's the entire point of embedding `token` in the URL query string rather than requiring cookies/basic auth), so a single leaked CCMenu URL (which is routinely embedded in third-party dashboards, browser extensions, or public status pages) grants read access to the deploy/build status of every stack managed by the Shipit instance, not just the one it was generated for. This includes stacks the token holder was never granted (even implicit) access to view via that mechanism.

### Likelihood Explanation
Likelihood is high: any authenticated Shipit user can trivially trigger this by requesting a CCMenu URL for any stack they can see, then reusing the resulting token against arbitrary `stack_id` values in `CCMenuController#show`. No privileged action, secret knowledge, or additional authentication boundary needs to be crossed beyond having once obtained a legitimately-issued CCMenu token (which by design ends up outside authenticated Shipit sessions, e.g. in a public dashboard).

### Recommendation
Bind the CCMenu `ApiClient` to the specific stack when it is created (`stack: stack` in `create_with`, and include `stack` in the `find_or_create_by!` key so a distinct client per stack is minted), and update `CCMenuController#stack` to resolve stacks through the same authorization-scoped path the rest of the API controllers use (via `current_api_client.stack_id` matching `params[:stack_id]`) instead of calling `Stack.from_param!` unscoped.

### Proof of Concept
1. As User X (has access to Stack A), call `GET /ccmenu_url?stack_id=A`. Response contains `ccmenu_url` with `token=T` for Stack A.
2. Inspect/obtain `T` (e.g. from the shared/public CCMenu widget where this URL is normally embedded).
3. Call `GET /api/stacks/B/ccmenu?token=T` for an unrelated Stack B.
4. Because `ApiClient` for `T` was created without `stack_id` and `CCMenuController#stack` resolves `params[:stack_id]` directly via `Stack.from_param!` rather than filtering through `current_api_client`'s authorized stack, the request succeeds and returns Stack B's latest deploy/rollback XML status, despite `T` never having been authorized for Stack B.

### Citations

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L6-23)
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

    def stack
      @stack ||= Stack.from_param!(params[:stack_id])
    end
  end
```

**File:** app/models/shipit/api_client.rb (L7-21)
```ruby
    belongs_to :creator, class_name: 'User'
    belongs_to :stack, optional: true

    validates :creator, :name, presence: true

    serialize :permissions, coder: Shipit.serialized_column(:permissions, type: Array)
    PERMISSIONS = %w[
      read:stack
      write:stack
      deploy:stack
      lock:stack
      read:hook
      write:hook
    ].freeze
    validates :permissions, subset: { of: PERMISSIONS }
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

**File:** app/controllers/shipit/api/base_controller.rb (L74-80)
```ruby
      def stacks
        @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
      end

      def stack
        @stack ||= stacks.from_param!(params[:stack_id])
      end
```
