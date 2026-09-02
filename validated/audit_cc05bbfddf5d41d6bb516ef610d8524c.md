### Title
CCMenu badge token created without a stack scope grants read access to any stack via `stack_id` reuse - (File: `app/controllers/shipit/ccmenu_url_controller.rb`, `app/controllers/shipit/api/ccmenu_controller.rb`)

### Summary
`CCMenuUrlController#client` creates/reuses an `ApiClient` with `read:stack` permission but never assigns `stack:`, leaving `stack_id` nil. `Api::CCMenuController#stack` then resolves the target stack with `Stack.from_param!(params[:stack_id])` directly, bypassing the `current_api_client.stack_id` scoping that `Api::BaseController#stacks`/`#stack` would otherwise apply, so the token authenticates against any `stack_id` supplied in the request.

### Finding Description
The binding that should hold is: `current_api_client.stack_id == stack.id` (or, absent that, `stacks` must be restricted to `Stack.where(id: current_api_client.stack_id)` when `stack_id` is present). In practice:

- `CCMenuUrlController#client` builds the token-bearing `ApiClient` via `ApiClient.create_with(permissions: %w[read:stack]).find_or_create_by!(creator: current_user, name: 'CCMenu Client')` with no `stack:` attribute, so `stack_id` is `nil`. [1](#0-0) 
- `ApiClient.authenticate` only verifies the signed row id and returns the record; it performs no stack check. [2](#0-1) 
- `Api::BaseController#stacks` is the only place that would honor `current_api_client.stack_id` (and even then, a nil `stack_id` intentionally means "all stacks", by design for globally-scoped clients created through the authenticated `ApiClientsController` UI). [3](#0-2) 
- `Api::CCMenuController` overrides `stack` to call `Stack.from_param!(params[:stack_id])` directly instead of the inherited `stacks.from_param!(params[:stack_id])`, and its `authenticate_api_client` override only authenticates the query-string token — it never cross-checks `current_api_client.stack_id` against the requested `stack_id`. [4](#0-3) 

Attacker flow: obtain a CCMenu badge URL that a legitimate user generated for stack A (e.g., embedded in a public README, CI dashboard, or shared link) via `GET /ccmenu/*stack_id` → `CCMenuUrlController#fetch`, which returns a URL of the form `/api/stacks/<owner>/<repo>/<branch>/ccmenu?token=<token>`. The attacker then replays the same `token` against an arbitrary `stack_id`: `GET /api/stacks/<other_owner>/<other_repo>/<branch>/ccmenu?token=<token>`. Because `authenticate_api_client` only validates the token signature and `stack` resolves `params[:stack_id]` unconditionally, the request succeeds and discloses the other stack's deploy/build status, name, and last build info.

Existing guards do not stop this: `require_permission :read, :stack` only checks the client's `permissions` array (`check_permissions!`) not stack association; there is no `verify_signature`/webhook check involved since this is a GET API endpoint; `ExplicitParameters`/model validators are irrelevant to authorization scoping here.

### Impact Explanation
Any holder of a leaked/shared CCMenu badge token (which is a `read:stack` token intended for a single stack) can read the CI/deploy status (`lastBuildStatus`, `lastBuildLabel`, `lastBuildTime`, lock state, etc.) of every stack in the Shipit installation, including stacks tied to private repositories, simply by varying the `stack_id` query/path parameter. This is a repeatable, unauthenticated (no session, no privileged token) cross-tenant information disclosure — matching the High severity category "unauthenticated read of stack state... or deploy output."

### Likelihood Explanation
Preconditions are low-cost and realistic: any authenticated Shipit user can click "Fetch URL" on a stack's settings page to mint a CCMenu URL (`app/views/shipit/stacks/settings.html.erb` "Fetch URL" button), and such URLs are commonly embedded in public places (README badges, status pages) since that is exactly CCMenu's purpose. No GitHub or Shipit secret is needed by the attacker — only the leaked token, which is designed to be shared. The attack is a single crafted GET request, fully repeatable against every stack_id in the instance.

### Recommendation
- In `CCMenuUrlController#client`, associate the created `ApiClient` with the requested `stack` (e.g., `find_or_create_by!(creator: current_user, stack: stack, name: 'CCMenu Client')`) so tokens are stack-scoped at creation.
- In `Api::CCMenuController#stack`, use the inherited scoped lookup (`stacks.from_param!(params[:stack_id])`) instead of `Stack.from_param!(params[:stack_id])` directly, and additionally reject the request (401/403) if `current_api_client.stack_id.present?` and it does not match the resolved stack.

### Proof of Concept
```ruby
# test/controllers/ccmenu_scope_test.rb
require 'test_helper'

module Shipit
  class CCMenuScopeTest < ActionController::TestCase
    tests Api::CCMenuController

    test "a CCMenu token minted without a stack association discloses other stacks" do
      user = shipit_users(:walrus)
      stack_a = shipit_stacks(:shipit)
      stack_b = Stack.create!(repository: Repository.new(owner: 'other', name: 'private-repo'), branch: 'main')

      # Mimic CcmenuUrlController#client: created with no stack association.
      client = ApiClient.create!(creator: user, name: 'CCMenu Client', permissions: %w[read:stack])
      assert_nil client.stack_id # binding precondition: current_api_client.stack_id == nil

      # Replay the token against an unrelated stack_id.
      get :show, params: { stack_id: stack_b.to_param, token: client.authentication_token }

      assert_response :ok # should have been :forbidden / :not_found for an unrelated stack
      assert_includes response.body, stack_b.to_param
    end
  end
end
```

### Citations

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L15-18)
```ruby
    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```

**File:** app/models/shipit/api_client.rb (L23-27)
```ruby
    class << self
      def authenticate(token)
        find_by(id: message_verifier.verify(token).to_i)
      rescue Shipit::SimpleMessageVerifier::InvalidSignature
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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L29-36)
```ruby
      def stack
        @stack ||= Stack.from_param!(params[:stack_id])
      end

      def authenticate_api_client
        @current_api_client = ApiClient.authenticate(params[:token])
        super unless @current_api_client
      end
```
