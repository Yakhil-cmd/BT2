### Title
API identity spoofing via unauthenticated `X-Shipit-User` header allows any authenticated `ApiClient` to attribute deploys/rollbacks/tasks/merges to an arbitrary Shipit `User` - (File: `app/controllers/shipit/api/base_controller.rb`)

### Summary
Shipit's REST API authenticates the caller by verifying a signed `ApiClient` token (`ApiClient.authenticate`), but the *acting user* attributed to write operations (deploys, rollbacks, task aborts, merge requests, locks, environment variables) is derived from the unsigned `X-Shipit-User` request header. That header is never covered by the token's HMAC and is never checked against any permission the `ApiClient`'s `creator` or its `permissions`/`stack_id` scope actually has, so any bearer of a valid (even minimally-privileged) API token can attribute actions to any Shipit `User`, including users who never authorized or performed the action.

### Finding Description
The binding that should hold is: `identity authenticated by the signed ApiClient token == identity attributed to the resulting Task/MergeRequest/Lock record`. Instead, `current_user` in the API layer is computed independently of the verified token: [1](#0-0) 

`authenticate_api_client` verifies only the `ApiClient` (an id signed with `Shipit.api_clients_secret`): [2](#0-1) 

The `identify_user` method then looks up an arbitrary `User` by matching the plaintext, attacker-supplied `X-Shipit-User` header against the `login` column — a field with no cryptographic relationship whatsoever to the token that was verified:
```ruby
def identify_user
  user_login = request.headers['X-Shipit-User'].presence
  User.where('lower(login) = ?', user_login.downcase).first if user_login
end
```
This is structurally identical to the report's root cause: a field (`from_chain` in the report, `X-Shipit-User` here) that is acted upon downstream but never included in the verification step (`verifySignature` in the report, `ApiClient.authenticate` here). The report's downstream consequence was corrupting `create_cross_txs[txid].status`; here the downstream consequence is corrupting attribution fields such as `Task#aborted_by`, deploy/rollback authorship, and merge-queue requester identity — all of which are used across the app for auditing, notifications, and "who did this" trust decisions.

`current_user` is used across the write-capable API controllers to attribute actions:
- `Api::TasksController#abort` sets `aborted_by` to whatever `current_user` resolves to, confirmed by test: [3](#0-2) 
- Similar `current_user` usage exists in `locks_controller.rb`, `release_statuses_controller.rb`, `rollbacks_controller.rb`, `deploys_controller.rb`, and `merge_requests_controller.rb`.

### Impact Explanation
Any party holding a valid `ApiClient` token — even one scoped to a single stack with minimal permissions (e.g. `deploy:stack` only) — can set `X-Shipit-User` to the login of any other Shipit user (an admin, a specific engineer, a bot) and have all resulting actions (deploy triggers, rollbacks, task aborts, merge-queue requests, environment-variable changes) recorded and attributed to that impersonated user. This breaks the authentication↔attribution binding the engine relies on for its audit trail, approvals, and any downstream automation/hooks that trust the "who did this" field, and can be used to frame another user for an unauthorized deploy/rollback or to bypass any user-specific expectations baked into deploy tooling. This satisfies the "unauthorized deploy/rollback" impact bucket, since the actor performing the write is not the identity the system will record and trust as having performed it.

### Likelihood Explanation
Likelihood is high for any consumer possessing a valid `ApiClient` credential (a normal, expected actor in this system, e.g. CI/CD integration tokens): the attack requires no additional secret, no race condition, and no privilege escalation beyond simply setting an HTTP header, which is explicitly documented/tested behavior of the API (`request.headers['X-Shipit-User']`).

### Recommendation
Do not allow the caller to freely choose the attributed `User` via an unauthenticated header. Either:
1. Bind `X-Shipit-User` cryptographically to the `ApiClient` token itself (e.g., only allow it to resolve to `api_client.creator`, or require it to be part of the signed message verified in `ApiClient.authenticate`), or
2. Require an explicit, permission-gated mapping (e.g., only API clients with a dedicated `impersonate:user` permission may supply `X-Shipit-User`, and only for users within the same `Shipit.github_teams` authorization boundary), or
3. Remove header-based user attribution entirely and attribute all API-driven actions to the `ApiClient`'s `creator` or to a distinguishable "API" pseudo-user.

### Proof of Concept
1. Obtain (or be issued) any valid `ApiClient` token scoped to a single stack with `deploy:stack` permission (`ApiClient#authentication_token`).
2. Send `PUT /api/stacks/<owner>/<repo>/<env>/tasks/<id>/abort` (or trigger a deploy/rollback) with `Authorization: Basic <token>` and header `X-Shipit-User: victim-admin-login`.
3. Observe `Task#aborted_by` (or the deploy/rollback/merge-request "requested by" field) is set to the `victim-admin-login` `User` record, as confirmed by the existing test: [3](#0-2) 
No verification ties the header value to the token holder's actual identity or permissions — the token's HMAC (step 1) never covers the `X-Shipit-User` value used in step 2/3.

### Citations

**File:** app/controllers/shipit/api/base_controller.rb (L48-72)
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

**File:** test/controllers/api/tasks_controller_test.rb (L118-126)
```ruby
      test "#abort sets `aborted_by` to the current user" do
        task = shipit_deploys(:shipit_running)
        task.ping
        request.headers['X-Shipit-User'] = @user.login

        put :abort, params: { stack_id: @stack.to_param, id: task.id }

        assert_equal task.reload.aborted_by, @user
      end
```
