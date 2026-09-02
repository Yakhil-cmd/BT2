### Title
Unauthenticated identity spoofing via `X-Shipit-User` header binds arbitrary actions to any Shipit `User` regardless of the authenticated `ApiClient` - ([File: app/controllers/shipit/api/base_controller.rb])

### Summary
The API authentication layer verifies the caller's identity as an `ApiClient` (a scoped bearer token with specific `permissions`), but the acting `User` recorded against privileged actions (deploy author, rollback author, lock owner, task/merge-request author) is derived from a client-supplied, unauthenticated `X-Shipit-User` HTTP header. The cryptographic binding that authorizes the request (`ApiClient` token verified via `SimpleMessageVerifier`) never covers this header, so the header's value can be freely chosen by anyone holding *any* valid `ApiClient` token, regardless of the `User` that token's `creator` represents.

### Finding Description
`Shipit::Api::BaseController#authenticate_api_client` verifies the request using HTTP Basic auth against `ApiClient.authenticate(token)`, which validates a signed token via `Shipit::SimpleMessageVerifier`: [1](#0-0) [2](#0-1) 

Separately, `current_user` — the identity attributed to the action being performed — is computed from an arbitrary request header that is not part of the verified token or any signature: [3](#0-2) 

This is confirmed by the test suite, which shows the deploy's `user` (author) is set directly from whatever login is passed in `X-Shipit-User`, with no ownership check tying that login to the authenticated `ApiClient`'s `creator`: [4](#0-3) 

The `ApiClient` model only binds `permissions` (`read:stack`, `write:stack`, `deploy:stack`, `lock:stack`, `read:hook`, `write:hook`) and an optional `stack_id` scope to the token; it has no relationship enforcing which `User` identities may be claimed via `X-Shipit-User`: [5](#0-4) 

Because `current_user` (derived from the spoofable header) is distinct from `current_api_client` (the entity actually authenticated by signature), the equality the system implicitly relies on — "the `User` whose identity is asserted == the identity cryptographically verified by the request" — is broken. The signature over the `ApiClient` token never covers the `X-Shipit-User` header value, so an attacker who obtains any `ApiClient` token (even one scoped to `deploy:stack` on a specific stack, created for automation/CI purposes) can impersonate any other Shipit `User`, including privileged/admin users, for every action performed through that token.

### Impact Explanation
This allows an attacker holding a valid `ApiClient` token (e.g., a CI-service token with only `deploy:stack` permission on one stack) to attribute deploys, rollbacks, locks, tasks, and merge-request operations to any arbitrary `Shipit::User` login by simply supplying an `X-Shipit-User` header. This undermines audit trails, approval/authorization workflows relying on `current_user` for permission checks in views/business logic (e.g. attribution used in notifications, Slack/webhooks, or any downstream logic keyed off `deploy.user`), and enables unauthorized-deploy-adjacent identity forgery — an unauthorized action is performed and falsely attributed to a legitimate/privileged account. This matches the impact criteria "unauthorized deploy, rollback ... " combined with identity/authentication bypass class of the binding rules (GitHub identity vs. `User` bound to session/request).

### Likelihood Explanation
Likelihood is high for anyone already possessing any valid `ApiClient` token (a low-privilege, automation-scoped credential), since exploitation requires only setting one HTTP header — no additional secrets, GitHub credentials, or session are needed. Any Shipit deployment that issues scoped API tokens to CI systems or partially-trusted integrations is exposed once such a token is compromised or intentionally used by its holder to attribute actions to another user.

### Recommendation
Do not derive `current_user` from an unauthenticated client-supplied header. Either remove `X-Shipit-User` entirely and always attribute actions to the authenticated `ApiClient` (or its `creator`), or require that the claimed login be validated against the `ApiClient`'s allowed identities (e.g., only allow the `ApiClient.creator`, or require a signed assertion of identity, not a bare header value).

### Proof of Concept
1. Obtain (or be issued) a valid `ApiClient` token scoped only to `deploy:stack` for stack A (e.g. a CI automation token).
2. Send: `POST /api/stacks/:stack_id/deploys` with header `X-Shipit-User: admin-login` and valid Basic-auth token for the above `ApiClient`.
3. Per `identify_user`, `current_user` resolves to the `User` with `login == 'admin-login'` regardless of who holds the token: [6](#0-5) 
4. The resulting `Deploy` is created with `user == admin-login`'s `User` record, as demonstrated by the existing test showing the header directly controls deploy authorship: [7](#0-6) 

Note: I was unable to fully review `app/controllers/shipit/api/locks_controller.rb`, `rollbacks_controller.rb`, `tasks_controller.rb`, `release_statuses_controller.rb`, and `merge_requests_controller.rb` contents (tool access ended before retrieval), though grep confirms they all reference `current_user`, suggesting the same spoofing binding likely extends to those actions as well; this should be verified directly in the repository.

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

**File:** app/models/shipit/api_client.rb (L1-21)
```ruby
# frozen_string_literal: true

module Shipit
  class ApiClient < Record
    InsufficientPermission = Class.new(StandardError)

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

**File:** app/models/shipit/api_client.rb (L23-32)
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
```

**File:** test/controllers/api/deploys_controller_test.rb (L49-61)
```ruby
      test "#create use the claimed user as author" do
        request.headers['X-Shipit-User'] = @user.login
        post :create, params: { stack_id: @stack.to_param, sha: @commit.sha }
        deploy = Deploy.last
        assert_equal @user, deploy.user
      end

      test "#create normalises the claimed user" do
        request.headers['X-Shipit-User'] = @user.login.swapcase
        post :create, params: { stack_id: @stack.to_param, sha: @commit.sha }
        deploy = Deploy.last
        assert_equal deploy.user, @user
      end
```
