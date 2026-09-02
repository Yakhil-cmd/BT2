### Title
CCMenu API token issued by `CCMenuUrlController#fetch` is a fully unscoped `read:stack` credential valid via Basic-Auth on every `Api::*Controller` - ([File: app/controllers/shipit/ccmenu_url_controller.rb])

### Summary
`CCMenuUrlController#fetch` mints an `ApiClient` token intended to be embedded in a public build-radiator URL, but the underlying `ApiClient` record is created with `permissions: %w[read:stack]` and no `stack` binding. Because `ApiClient.authenticate` and `BaseController#authenticate_api_client` treat any valid signed token identically regardless of transport (query string vs. Basic-Auth) or originating controller, that same token also authenticates as Basic-Auth credentials against any other `Api::*Controller` requiring `read:stack` (e.g. `Api::CommitsController`), granting read access to every stack in the installation, not just the one the radiator URL was generated for.

### Finding Description
The intended binding should be: *token issued for stack S via `CCMenuUrlController#fetch` == credential valid only for reading stack S via the CCMenu endpoint*. That binding is broken because:

1. `CCMenuUrlController#client` creates/reuses the client without any stack scoping: [1](#0-0) 
2. `ApiClient.authenticate` verifies the token purely by signed id, independent of scope or transport: [2](#0-1) 
3. Because `stack_id` is nil, `BaseController#stacks` (used by every other `Api::*Controller`, including `Api::CommitsController`) resolves to `Stack.all`, not the single stack the URL was generated for: [3](#0-2) 
4. `BaseController#authenticate_api_client` accepts the exact same token format via HTTP Basic-Auth for any other controller in the `Api::*` namespace: [4](#0-3) 
5. `Api::CommitsController` (and other `Api::*Controller`s) only require the generic `read:stack` permission bit, with no additional stack-specific check: [5](#0-4) 

The test suite itself demonstrates that `client.authentication_token` is interchangeably valid as a query-string token (CCMenu) or a Basic-Auth password (any other API controller): `test/helpers/api_helper.rb` uses `Base64.encode64(client.authentication_token)` as the Basic-Auth header for generic API controller tests, and `test/controllers/api/ccmenu_controller_test.rb` uses the same token as `params[:token]`. No mechanism in `ApiClient`, `BaseController`, or `CCMenuController` binds the token to a single stack or a single transport/controller.

Exploit flow: a user with a Shipit session calls `GET /ccmenu_url?stack_id=stack-A`, obtaining a URL with an embedded token. That URL is displayed publicly (its documented purpose — embedding in a build-radiator/CI dashboard). Anyone who can view that URL extracts `token` and sends `GET /api/stacks/stack-B/commits` with `Authorization: Basic <base64(token)>`. Since the `ApiClient` behind the token has `permissions: ['read:stack']` and `stack_id` nil, `require_permission!(:read, :stack)` passes and `stack` resolves to `stack-B`, returning its commit history — a stack completely unrelated to the one the CCMenu URL was created for.

### Impact Explanation
Any holder of a single CCMenu URL's token — intended only to let a build-radiator tool poll one stack's build status via XML — gains a general-purpose, cross-tenant `read:stack` API credential. It can be replayed against `Api::CommitsController`, and any other `Api::*Controller` gated only by `read:stack`, to read commit history, task/deploy metadata, and other stack state for every stack in the Shipit installation, not just the one it was issued for. This matches "High - unauthenticated read of stack state" since the credential's blast radius is not bound to the authorization context in which it was created or displayed, and it is fully repeatable (the signed token does not expire or rotate).

### Likelihood Explanation
No Shipit or GitHub secrets are required by the exploiting party — only possession of a previously-issued CCMenu URL, which is explicitly designed to be embedded in public/shared CI-radiator displays or config files. The requesting cost is a single HTTP GET with a Basic-Auth header built from the already-visible token; no signature forgery or brute force is needed. The only precondition is that some legitimate Shipit user has generated at least one CCMenu URL for a stack, which is a normal/documented feature (`app/views/shipit/stacks/settings.html.erb` exposes the "Get CCMenu URL" action).

### Recommendation
Scope the `ApiClient` created by `CCMenuUrlController#fetch` to the specific stack (set `stack: stack` when creating/finding it) so `stacks` resolves to only that stack for every `Api::*Controller`, and/or restrict the CCMenu-issued client's permissions/verification to the `CCMenuController` endpoint only (e.g., a distinct signed-token namespace/verifier that `BaseController#authenticate_api_client` does not accept).

### Proof of Concept
```ruby
test "ccmenu token is not scoped to the stack it was issued for" do
  stack_a = shipit_stacks(:shipit)
  stack_b = Stack.create!(repository: Repository.new(owner: "foo", name: "bar"), branch: "main")

  user = shipit_users(:walrus)
  sign_in(user)
  get :fetch, params: { stack_id: stack_a.to_param } # CCMenuUrlController#fetch
  token = URI(JSON.parse(response.body)["ccmenu_url"]).query[/token=([^&]+)/, 1]

  @request.headers["Authorization"] = "Basic #{Base64.encode64(CGI.unescape(token))}"
  get :index, controller: "shipit/api/commits", params: { stack_id: stack_b.to_param }
  assert_response :ok # should be :forbidden/:not_found if properly scoped to stack_a
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

**File:** app/controllers/shipit/api/base_controller.rb (L74-80)
```ruby
      def stacks
        @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
      end

      def stack
        @stack ||= stacks.from_param!(params[:stack_id])
      end
```

**File:** app/controllers/shipit/api/commits_controller.rb (L1-13)
```ruby
# frozen_string_literal: true

module Shipit
  module Api
    class CommitsController < BaseController
      require_permission :read, :stack

      def index
        commits = stack.commits.reachable.includes(:statuses)
        commits = commits.newer_than(stack.last_deployed_commit) if params[:undeployed]

        render_resources(commits)
      end
```
