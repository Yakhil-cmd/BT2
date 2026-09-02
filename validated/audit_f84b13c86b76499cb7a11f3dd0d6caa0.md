## Finding: CCMenu API token created without stack scoping grants cross-stack read access

### Title
Unscoped `read:stack` `ApiClient` issued by CCMenu URL controller authorizes reading every stack, not just the requesting one - (File: `app/controllers/shipit/ccmenu_url_controller.rb`)

### Summary
`CCMenuUrlController#fetch` mints an `ApiClient` token intended to expose a single stack's CI status to CCMenu-compatible build monitors, but the client record is created without a `stack` association, so the resulting token is treated as instance-wide by `Api::BaseController`.

### Finding Description
`CCMenuUrlController#fetch` builds (or reuses) an `ApiClient` scoped only by `permissions: %w[read:stack]`, without setting `stack:`: [1](#0-0) 

The token embedded in the returned `ccmenu_url` is this client's `authentication_token`, generated from `ApiClient#authentication_token` / `message_verifier`: [2](#0-1) 

When that token is later presented (e.g., to `Api::CCMenuController#show`), `Api::BaseController#stacks` decides the authorization scope purely from whether the client has a `stack_id`: [3](#0-2) 

Because `stack:` was never assigned on creation, `current_api_client.stack_id?` is `false`, so `stacks` resolves to `Stack.all` instead of the single stack the UI/URL implied. `Api::CCMenuController#stack` then does `stacks.from_param!(params[:stack_id])`, letting the caller pick *any* stack ID while still authenticating with a token that was only ever meant for one stack: [4](#0-3) 

The binding broken: **stack a token authorizes (the single stack for which the CCMenu URL was fetched)** ≠ **stack it actually touches (`Stack.all`, i.e. every stack in the Shipit instance)**.

### Impact Explanation
CCMenu URLs are designed to be handed to third-party build-status monitors and are visible in browser history, shared dashboards, and referer headers — they are treated as "low sensitivity, single project" credentials by design (`CCMenuUrlController` doc comment/UI: "Fetch URL" button per stack). Because the underlying `ApiClient` is not stack-scoped, anyone in possession of one such URL/token can query `/api/stacks/*/ccmenu` for *every* stack across every repository managed by the Shipit instance, reading deploy/task status and stack metadata that belongs to repositories the token holder was never granted visibility into. This matches the in-scope High-impact category: unauthenticated/unauthorized read of stack state via a credential whose intended scope was a single repository/stack.

### Likelihood Explanation
Any authenticated Shipit user (no special privilege needed) can trigger this by visiting their own stack's Settings page and clicking "Fetch URL" (`ccmenu_url_url`), which is standard, expected usage — the resulting token is exactly as strong as one covering the whole instance. No attacker interaction with GitHub, webhooks, or another user's account is required; the flaw is purely in how the token's scope is (mis)established at creation time.

### Recommendation
Set `stack:` explicitly when creating/finding the `ApiClient` in `CCMenuUrlController#client`, e.g. `ApiClient.create_with(permissions: %w[read:stack], stack:).find_or_create_by!(creator: current_user, stack:, name: 'CCMenu Client')`, so `stack_id?` is true and `Api::BaseController#stacks` correctly restricts the token to the originating stack only.

### Proof of Concept
1. As any logged-in Shipit user with access to Stack A, call `GET /ccmenu/*stack_id` for Stack A (or click "Fetch URL" in the UI) to obtain `ccmenu_url` containing `token=<T>`. [5](#0-4) 
2. Using token `T`, call `GET /api/stacks/<OtherOrg>/<OtherRepo>/<env>/ccmenu?token=T` for a stack the user has no access to.
3. Because `ApiClient#stack_id?` is `false` for `T`, `Api::BaseController#stacks` returns `Stack.all`, `Api::CCMenuController#stack` resolves the unrelated stack, `require_permission :read, :stack` passes (permission `read:stack` is present, it's just not restricted to a stack), and the attacker receives that stack's latest deploy/build status. [3](#0-2) [6](#0-5)

### Citations

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

**File:** app/models/shipit/api_client.rb (L23-36)
```ruby
    class << self
      def authenticate(token)
        find_by(id: message_verifier.verify(token).to_i)
      rescue Shipit::SimpleMessageVerifier::InvalidSignature
      end

      def message_verifier
        @message_verifier ||= Shipit::SimpleMessageVerifier.new(Shipit.api_clients_secret)
      end
    end

    def authentication_token
      self.class.message_verifier.generate(id)
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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L5-36)
```ruby
    class CCMenuController < BaseController
      require_permission :read, :stack

      class NoDeploy
        def id
          0
        end

        def ended_at
          Time.now.utc
        end

        def running?
          false
        end
      end

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
