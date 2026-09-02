### Title
CCMenu API token issued for a single stack actually authorises read access to every stack - ([File: app/controllers/shipit/ccmenu_url_controller.rb])

### Summary
`CCMenuUrlController#fetch` is meant to hand a caller a scoped `read:stack` token for exactly the stack named in `params[:stack_id]`. Because the `ApiClient` is looked up/created by `creator` + `name` only, and `stack` is never assigned on creation, the resulting token's `stack_id` is `nil`, which the API authorization layer treats as "unscoped" (all-stacks) access instead of the intended single-stack scope. [1](#0-0) [2](#0-1) 

### Finding Description
`CCMenuUrlController#fetch` builds a URL to the API's CCMenu endpoint for the requested `stack` and attaches an authentication token from `client`: [3](#0-2) 

`client` is defined as:
```ruby
def client
  @client ||= ApiClient.create_with(permissions: %w[read:stack])
                       .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
end
```
`find_or_create_by!` scopes the lookup/creation strictly to `creator` and `name` - the current stack is never passed to `create_with`, nor is it part of the lookup criteria. Consequently:
- On first call for any stack, an `ApiClient` row is created with `permissions: ['read:stack']` and `stack_id: nil` (the `belongs_to :stack, optional: true` association is left unset). [4](#0-3) 
- On every subsequent call, for *any other stack*, the same single `ApiClient` record (name "CCMenu Client", same creator) is found and reused, still with `stack_id: nil`.

The authorization layer used by the API base controller interprets a client with no `stack_id` as unrestricted:
```ruby
def stacks
  @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
end
```
`stack_id?` is `false` when `stack_id` is `nil`, so `stacks` resolves to `Stack.all`. [5](#0-4) 

This breaks the intended binding: **the stack a token authorises (the one named in the CCMenu URL request, `params[:stack_id]`) ≠ the stack(s) the token actually touches (every stack in the installation)**. The CCMenu token is a bearer credential embedded in a plain URL (`?token=...`), designed to be handed to third‑party CI dashboard tools (CCMenu clients) that poll build status. Any leak of that URL (browser history, screenshots, proxy/access logs, a compromised or malicious CCMenu-consuming tool) grants read access to the state, deploy history, and task output of every stack in the Shipit installation - not just the one stack the user intended to expose.

### Impact Explanation
This is a High severity finding under the "unauthenticated read of stack state, task streams or deploy output" category: possession of a token that was only meant to expose one stack's CCMenu status now grants `read:stack` (`GET`) access across all stacks via the API (`Api::StacksController#index/#show`, `Api::CCMenuController#show`, deploy/task listing endpoints scoped through `current_api_client`). Any user who legitimately generates a CCMenu URL for one low‑sensitivity stack ends up holding a credential that discloses every other stack's state, including potentially more sensitive environments. [5](#0-4) [6](#0-5) 

### Likelihood Explanation
No privileged access is required beyond being a normal, already-authenticated Shipit user who can view any stack's settings page (where the CCMenu URL feature is exposed) and click "Get CCMenu URL". This is a single unprivileged UI action; the resulting token is then handled/stored as a low-sensitivity CI-widget credential (often pasted into external tooling), making accidental over-broad exposure likely once the URL leaves the trusted browser session. [7](#0-6) 

### Recommendation
- Scope the `ApiClient` lookup/creation to the specific stack: include `stack:` in both `create_with` and `find_or_create_by!` (e.g. `ApiClient.create_with(permissions: %w[read:stack], stack:).find_or_create_by!(creator: current_user, stack:, name: 'CCMenu Client')`), so each stack gets its own scoped client/token.
- Add a model-level invariant/validation ensuring any `ApiClient` created through this controller always has `stack_id` present, and add a regression test asserting that a CCMenu token minted for stack A returns `403`/empty results when used against stack B's API endpoints.

### Proof of Concept
1. User (any authenticated Shipit user) opens Stack A's settings page and requests its CCMenu URL: `GET /stacks/org/repoA/envA/ccmenu_url`.
2. `CCMenuUrlController#client` creates `ApiClient` #1: `creator: user`, `name: 'CCMenu Client'`, `permissions: ['read:stack']`, `stack_id: nil`. The response contains `token1` bound to that `ApiClient` id.
3. The same user (or anyone who obtains `token1`, e.g. via a leaked/shared CCMenu widget URL) calls `GET /api/stacks?...` or `GET /api/stacks/:stack_id/ccmenu.xml` with `Authorization: Basic base64(token1)` (or as the `token` query param for the ccmenu XML endpoint) for **Stack B**, which the token was never issued for.
4. `authenticate_api_client` resolves `current_api_client` to `ApiClient` #1; `stacks` computes `Stack.all` because `stack_id?` is false, so the request against Stack B succeeds and returns Stack B's data — proving the token authorised more than the single stack it was requested for. [8](#0-7)

### Citations

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L7-18)
```ruby
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

**File:** app/controllers/shipit/api/base_controller.rb (L48-80)
```ruby
      def authenticate_api_client
        @current_api_client = if Shipit.disable_api_authentication
                                UnlimitedApiClient.new
                              else
                                BasicAuth.authenticate(request) do |*parts|
                                  token = parts.select(&:present?).join('--')
                                  ApiClient.authenticate(token)
                                end
                              end
        return if @current_api_client

        headers['WWW-Authenticate'] = 'Basic realm="Authentication token"'
        render(status: :unauthorized, json: { message: 'Bad credentials' })
      end

      attr_reader :current_api_client

      def current_user
        @current_user ||= identify_user || AnonymousUser.new
      end

      def identify_user
        user_login = request.headers['X-Shipit-User'].presence
        User.where('lower(login) = ?', user_login.downcase).first if user_login
      end

      def stacks
        @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
      end

      def stack
        @stack ||= stacks.from_param!(params[:stack_id])
      end
```

**File:** app/models/shipit/api_client.rb (L7-8)
```ruby
    belongs_to :creator, class_name: 'User'
    belongs_to :stack, optional: true
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

**File:** app/views/shipit/stacks/settings.html.erb (L1-1)
```erb
<%= render partial: 'shipit/stacks/header', locals: { stack: @stack } %>
```
