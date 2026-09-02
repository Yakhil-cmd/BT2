Based on the investigation, I found a genuine analog matching the required bug class: the `X-Shipit-User` header is used to attribute authorship of privileged actions (deploys, rollbacks), but this header is not covered by the API token's cryptographic verification, and any string is accepted to look up a `User` without confirming the caller's actual identity.

### Title
Author identity spoofing via unauthenticated `X-Shipit-User` header - (File: app/controllers/shipit/api/base_controller.rb)

### Summary
The API's `ApiClient` bearer token authenticates *the caller's permission scope* (via `Shipit::SimpleMessageVerifier`), but the `User` bound to the request — used as the recorded author/actor of deploys, rollbacks, locks, and release statuses — is derived from the unauthenticated `X-Shipit-User` request header.

### Finding Description
`BaseController#current_user` resolves the acting user purely from a client-supplied header, with no cryptographic binding to the verified API token: [1](#0-0) 

`ApiClient.authenticate` only verifies that the bearer token maps to a valid client id via `message_verifier.verify(token)` — it authenticates the *client* and its `permissions`/`stack_id` scope, not any particular GitHub identity: [2](#0-1) 

Any holder of a valid API token (which only needs `deploy:stack` / `lock:stack` permission, not any relationship to a specific person) can set `X-Shipit-User` to the login of any existing `Shipit::User` — e.g. an admin, a team lead, or a specific engineer — and every privileged action performed with that token will be attributed to the impersonated user. This is exercised directly in the test suite: `X-Shipit-User` is trusted to set `deploy.user`, `rollback.user`, and (via `current_user`) the actor recorded on locks/release statuses: [3](#0-2) [4](#0-3) 

The binding that should hold is: `identity authenticated by the token` **=** `identity credited as the actor of the deploy/rollback/lock`. Instead, the token only authenticates *permission scope*, while the *actor identity* is taken from an arbitrary, unsigned header value — analogous to the oracle report's core defect: a value is consumed and acted upon (here, attributed authorship enabling audit-trail/accountability decisions) without being covered by the actual verification performed (here, the signed API token).

### Impact Explanation
This does not grant new *capabilities* beyond what the token's `permissions` already allow, but it breaks the accountability/audit-trail guarantee that Shipit's UI and history rely on to determine "who deployed/rolled back/locked this stack." Any script or integration holding a `deploy:stack` token can trigger and permanently attribute a deploy, rollback, or lock to any other user in the system (e.g., a manager, a specific engineer for blame-shifting, or a bot with elevated visibility), and downstream consumers (audit logs, notifications, `SHIPIT_USER`/`EMAIL`/`GIT_COMMITTER_NAME` environment variables passed into deploy scripts) will reflect the impersonated identity. This falls short of RCE/token exfiltration but represents a genuine authentication-binding violation with no privilege boundary enforcing it.

### Likelihood Explanation
Any party already possessing a valid `ApiClient` token with `deploy:stack`, `lock:stack`, or similar permission (a routine, documented integration credential, not a privileged secret beyond the token itself) can trivially exploit this on every request by setting one header. No race condition, timing, or GitHub-side trust is required.

### Recommendation
Do not derive the acting `User` from an arbitrary client-supplied header. If per-user attribution from integrations is required, bind the allowed `X-Shipit-User` value to the `creator` of the `ApiClient` (or to an explicitly configured allow-list on the `ApiClient` record), or require a signed assertion of identity rather than a plain header echoed back into `identify_user`.

### Proof of Concept
1. Obtain a valid `ApiClient` authentication token with `deploy:stack` permission (any legitimate CI integration credential).
2. `POST /api/stacks/:stack_id/deploys` with `Authorization: Basic <token>` and header `X-Shipit-User: <victim-login>` (any existing user's login), per `identify_user`'s lookup: [5](#0-4) 
3. The resulting `Deploy` (or `Rollback`, via `Api::RollbacksController#create`) is created with `deploy.user == victim`, as confirmed by the existing test `"#create use the claimed user as author"`: [6](#0-5) 
4. The victim's identity now appears as the author of the deploy in the UI, hooks payloads, and the `GIT_COMMITTER_NAME`/`SHIPIT_USER` environment variables passed to the deploy script.

### Citations

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

**File:** app/controllers/shipit/api/locks_controller.rb (L11-26)
```ruby
      def create
        if stack.locked?
          render(json: { message: 'Already locked' }, status: :conflict)
        else
          stack.lock(params.reason, current_user)
          render_resource(stack)
        end
      end

      params do
        requires :reason, String, presence: true
      end
      def update
        stack.lock(params.reason, current_user)
        render_resource(stack)
      end
```
