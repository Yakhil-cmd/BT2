## Finding: CCMenu API token scope bypass — token authorized for one stack is honored for any stack [1](#0-0) [2](#0-1) [3](#0-2) 

### Title
CCMenu ApiClient token scoping bypass allows reading any stack's state - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
The reported bug class is an index/field mismatch that causes a value validated for one purpose to be reused for another, unauthenticated purpose. The equivalent binding break in shipit-engine is between "the `stack_id` a `ApiClient` token is scoped to" and "the `stack_id` param that is actually queried" in the CCMenu endpoints.

### Finding Description
`CCMenuUrlController#client` mints (or reuses) an `ApiClient` for the current user without ever setting `stack:`, matching purely on `creator` and a fixed name:

```ruby
def client
  @client ||= ApiClient.create_with(permissions: %w[read:stack])
                       .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
end
``` [4](#0-3) 

The generated URL embeds `stack_id: stack.to_param` as a query parameter alongside the client's signed `authentication_token`, implying the URL is scoped to that one stack:
```ruby
def fetch
  uri = URI(api_stack_ccmenu_url(stack_id: stack.to_param))
  uri.query = { 'token' => client.authentication_token }.to_query
  render(json: { ccmenu_url: uri.to_s })
end
``` [5](#0-4) 

However, `Shipit::Api::CCMenuController` overrides both authentication and stack lookup to bypass the scoping mechanism that `BaseController` provides elsewhere:
```ruby
def stack
  @stack ||= Stack.from_param!(params[:stack_id])
end

def authenticate_api_client
  @current_api_client = ApiClient.authenticate(params[:token])
  super unless @current_api_client
end
``` [6](#0-5) 

Compare this to `BaseController#stacks`/`#stack`, which properly restricts the queryable set of stacks to the token's own `stack_id` when one is set:
```ruby
def stacks
  @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
end

def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
``` [7](#0-6) 

`ApiClient#check_permissions!` only checks that the token *has* the `read:stack` permission label; it never checks which stack the token is bound to:
```ruby
def check_permissions!(operation, scope)
  required_permission = "#{operation}:#{scope}"
  unless permissions.include?(required_permission)
    raise InsufficientPermission, ...
  end
  true
end
``` [8](#0-7) 

Because `ApiClient#authenticate` only reverses a signed id (`message_verifier.verify(token).to_i`) with no stack claim embedded in the signed payload itself, and because the same unscoped "CCMenu Client" record is reused across all of a user's stacks (`find_or_create_by!(creator:, name: 'CCMenu Client')` — no `stack:` in the match/create attributes), a single generated `ccmenu_url` token is valid for **every** stack, not just the one it was minted for. The binding that should hold — `token.stack_id == requested stack_id` — is never enforced in `Api::CCMenuController`, unlike every other API endpoint that inherits `BaseController#stack`.

### Impact Explanation
`api_stack_ccmenu_url` links are designed to be embedded in third-party, unauthenticated CI-status dashboards (CCMenu/CCTray clients) scoped to a single stack. Anyone who obtains one such leaked/shared URL (a token intended to disclose only one stack's build status) can substitute an arbitrary `stack_id` in the query string and read the CI/deploy state (`lastBuildStatus`, `lastBuildLabel`, `activity`, lock status, etc.) of **any** stack in the Shipit instance — including stacks belonging to different repositories/teams the token holder was never meant to see — without ever authenticating as a Shipit user. This is an unauthenticated disclosure of stack state, matching the High-severity class "unauthenticated read of stack state... via a token whose intended scope does not match the resource it is allowed to touch."

### Likelihood Explanation
Any Shipit user can generate one of these tokens for a stack they can view, and CCMenu URLs are explicitly meant to be pasted into external dashboards/tools (that's the entire point of the feature), which increases the odds of the URL/token leaking into a less-trusted context. Once leaked, exploitation requires nothing more than editing the `stack_id` query parameter — no special access, no cryptographic effort.

### Recommendation
Have `CCMenuUrlController#client` create/find an `ApiClient` actually scoped to the target stack (`stack:` attribute set, and matched on in `find_or_create_by!`), and change `Api::CCMenuController#stack` to reuse the scoped lookup from `BaseController` (i.e., `stacks.from_param!(params[:stack_id])`) instead of `Stack.from_param!(params[:stack_id])`, so the token's `stack_id` binding is actually enforced.

### Proof of Concept
1. As User A, visit a stack you have access to and request its CCMenu URL, e.g. `GET /stacks/orgA/repoA/production/ccmenu_url` → receive `https://shipit.example.com/api/stacks/orgA/repoA/production/ccmenu.xml?token=<TOKEN>`.
2. Take `<TOKEN>` and replace the `stack_id` path segment with a different stack the token was never intended for, e.g. `GET /api/stacks/orgB/repoB/staging/ccmenu.xml?token=<TOKEN>`.
3. Observe that `Api::CCMenuController#show` succeeds and returns `orgB/repoB`'s build/deploy status, because `authenticate_api_client` only validates the token's signature/id and `stack` performs an unscoped `Stack.from_param!` lookup, ignoring `current_api_client.stack_id`.

### Citations

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L1-24)
```ruby
# frozen_string_literal: true

require 'uri'

module Shipit
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
end
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L1-39)
```ruby
# frozen_string_literal: true

module Shipit
  module Api
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
    end
  end
end
```

**File:** app/controllers/shipit/api/base_controller.rb (L63-80)
```ruby
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
