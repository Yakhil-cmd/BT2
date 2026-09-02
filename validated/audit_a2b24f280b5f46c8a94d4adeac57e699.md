### Title
Unauthenticated `X-Shipit-User` header spoofs `current_user` identity for API-driven merges/deploys - (File: app/controllers/shipit/api/base_controller.rb)

### Summary
`Shipit::Api::BaseController#identify_user` resolves `current_user` purely from the client-supplied `X-Shipit-User` request header, with no cryptographic or session binding to the caller that passed `authenticate_api_client`. When `Shipit.disable_api_authentication` is true, `authenticate_api_client` accepts every request as an `UnlimitedApiClient` without checking any token, so any unauthenticated caller can set `X-Shipit-User` to an arbitrary login and have actions such as `MergeRequestsController#update` attribute a merge to that spoofed identity.

### Finding Description
The binding the engine implicitly relies on is: `current_user == the identity that authenticated via current_api_client`. In code, that binding is broken: [1](#0-0) [2](#0-1) 

`authenticate_api_client` only checks `Shipit.disable_api_authentication`; when true it assigns `UnlimitedApiClient.new` unconditionally, performing no basic-auth or token verification at all. Separately, `identify_user` reads `request.headers['X-Shipit-User']` verbatim and looks up a `User` by that login with zero verification that it corresponds to the entity that passed `authenticate_api_client` (there is none in this mode) or any signature/session proof. These two independently-controlled values (`current_api_client` and `current_user`) are never tied together.

`MergeRequestsController#update` passes this unverified `current_user` straight into the domain action: [3](#0-2) 

`MergeRequest.request_merge!(stack, params[:id], current_user)` stores this as `merge_requested_by`, which is used for audit/attribution of the merge action.

Attacker request: `PATCH /api/stacks/:stack_id/merge_requests/:id` with header `X-Shipit-User: <victim-login>` and no `Authorization` header at all — while the host has `Shipit.disable_api_authentication = true`.

No existing guard intercepts this: `require_permission!` only checks `current_api_client.check_permissions!`, and `UnlimitedApiClient` grants all permissions by design in this mode; there is no check anywhere that `current_user`'s login corresponds to any authenticated principal.

### Impact Explanation
Any unauthenticated caller who can reach the API can make `MergeRequest.request_merge!` (and, by the same `identify_user` mechanism, other actions across the API surface, e.g. deploys/rollbacks) run under an attacker-chosen identity for any stack reachable via `UnlimitedApiClient` (which is unrestricted, i.e., all stacks). This directly maps to the "unauthorized deploy, rollback or merge" Critical impact category and to falsely attributing an action to an arbitrary Shipit user, once the host operates with `disable_api_authentication` enabled. The action is fully repeatable across arbitrary stacks/repositories in a single request each time (only bounded by whatever real-world audit consequences the spoofed attribution has).

### Likelihood Explanation
This requires the deployment-level precondition `Shipit.disable_api_authentication = true`, which is documented as a host configuration flag (see `test/dummy/config/environments/development.rb` usage) rather than a default production setting; it is intended for internal/trusted-network deployments. Under that precondition, the attack costs nothing more than a single unauthenticated HTTP request with an arbitrary header — no credentials, tokens, or secrets are needed. Per the question's own rules, this precondition is in-scope because the engine code itself, once that flag is set, performs zero verification tying `X-Shipit-User` to any authenticated entity — the engine does not additionally validate the header against a trusted proxy, session, or signed value.

### Recommendation
Do not derive `current_user` from a raw, unauthenticated header. If `X-Shipit-User` is meant to support the `disable_api_authentication` (trusted-internal-network) mode, its value must be established via a mechanism the untrusted caller cannot influence (e.g. only allow it in `UnlimitedApiClient` mode from a well-defined trusted reverse proxy IP list, or accompany it with a signed/mac-verified assertion using `Shipit.api_clients_secret`), or bind `current_user` to properties of an authenticated `ApiClient`/session instead of a bare, always-present header.

### Proof of Concept
```ruby
# test/controllers/api/merge_requests_controller_test.rb (new test)
require 'test_helper'

module Shipit
  module Api
    class MergeRequestsControllerSpoofTest < ApiControllerTestCase
      setup do
        Shipit.disable_api_authentication = true
        @stack = shipit_stacks(:shipit)
        @victim = shipit_users(:walrus) # privileged/other user
        @merge_request = shipit_merge_requests(:shipit_pending)
      end

      teardown do
        Shipit.disable_api_authentication = false
      end

      test "identity spoofing via X-Shipit-User with API auth disabled" do
        request.headers['X-Shipit-User'] = @victim.login
        # no Authorization header set at all

        patch :update, params: { stack_id: @stack.to_param, id: @merge_request.number }

        # Binding under test: current_user should equal AnonymousUser (no verified identity),
        # but instead equals the attacker-supplied victim identity.
        assert_equal @victim, @controller.send(:current_user)
        assert_equal @victim, @merge_request.reload.merge_requested_by
      end
    end
  end
end
```
This demonstrates that with `disable_api_authentication` true and no `Authorization` header, `current_user` (and consequently `merge_requested_by`) equals the attacker-chosen `@victim` rather than `AnonymousUser`, confirming the broken binding.

### Citations

**File:** app/controllers/shipit/api/base_controller.rb (L48-61)
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
```

**File:** app/controllers/shipit/api/base_controller.rb (L65-72)
```ruby
      def current_user
        @current_user ||= identify_user || AnonymousUser.new
      end

      def identify_user
        user_login = request.headers['X-Shipit-User'].presence
        User.where('lower(login) = ?', user_login.downcase).first if user_login
      end
```

**File:** app/controllers/shipit/api/merge_requests_controller.rb (L17-18)
```ruby
      def update
        merge_request = MergeRequest.request_merge!(stack, params[:id], current_user)
```
