### Title
API clients can attribute privileged Shipit actions (lock, merge, deploy) to any GitHub-authenticated user via the unauthenticated `X-Shipit-User` header - (File: app/controllers/shipit/api/base_controller.rb)

### Summary
### Finding Description
The reported bug class is a **binding mismatch**: one identity/reference is verified/authorized, while a *different* identity/reference is the one actually acted upon (staked funds tracked against the old gauge while the admin's authorization only covers the new gauge). The same class of bug exists in Shipit's API layer between the entity that is cryptographically authenticated (the `ApiClient`) and the entity that is recorded/used as the actor of the operation (the `User`).

`Api::BaseController` authenticates the caller purely as an `ApiClient` via HTTP Basic auth against a signed token: [1](#0-0) 

But `current_user` — the identity attributed to the action (lock reason author, merge requester, task author/`aborted_by`, etc.) — is derived from a client-supplied, **unauthenticated** HTTP header, with no signature, session, or GitHub verification at all: [2](#0-1) 

Any caller holding *any* valid `ApiClient` token (e.g., a low-privilege integration token scoped only to `read:stack`/`deploy:stack` for one stack) can set `X-Shipit-User: <victim-login>` and have Shipit treat the request as if it were performed by that arbitrary existing `User` row — including admins, GitHub-team members, or bot accounts — without any proof of GitHub identity. This breaks the same equality the report highlights: `authenticated principal == acted-upon principal`. Here: `ApiClient (authenticated via Basic auth token)` != `User (attributed as actor of the operation)`, yet the code silently treats the header value as authoritative.

This identity is then used directly to perform trust-sensitive, stateful actions:
- Locking a stack with an attributed `current_user`: [3](#0-2) 
- Requesting a merge as `current_user`: [4](#0-3) 
- Triggering a task/deploy attributed to `current_user`: [5](#0-4) 

Note that `ApiClient` permission checks (`read:stack`, `write:stack`, `deploy:stack`, `lock:stack`) are enforced against the *client*, not the impersonated user, so this is not merely a UI cosmetic issue — it lets a caller falsify *whose* GitHub identity authorized/performed a privileged, audited operation (deploy trigger, rollback, merge request, stack lock) while only holding a narrowly-scoped `ApiClient` credential.

### Impact Explanation
This maps to escalation of trust attribution for unauthorized/deploy-adjacent operations: an attacker (or a compromised low-privilege integration) that only possesses an `ApiClient` token can cause Shipit to record and act as though a specific `User` (potentially an admin or a member of `Shipit.github_teams`) triggered a deploy, requested a merge, or locked/unlocked a stack. This corrupts the audit trail that Shipit's web authentication layer relies on (`Authentication#force_github_authentication`, `User#authorized?` checked against `Shipit.github_teams`) and can be used to mask the true origin of a malicious deploy/merge/lock action as coming from a trusted, authorized identity — directly touching the "escalation into `Shipit.github_teams` authorization" impact category, since all identity/authorization assumptions built on `current_user` in the web UI (team membership, `authorized?`) are trivially forgeable through this API path.

### Likelihood Explanation
Any party issued a scoped `ApiClient` token (a common integration credential, e.g. CI/CD systems, chatops bots) can exploit this with a single HTTP header, no additional access needed. Because `ApiClient` tokens are routinely handed to third-party integrations with only narrow permissions (`deploy:stack`, `lock:stack`), the ease of forging `current_user` via `X-Shipit-User` makes this readily reachable without any GitHub-side compromise.

### Recommendation
Do not derive `current_user` from a client-controlled request header. If per-user attribution over the API is required, it should be tied to a verified identity (e.g., a signed/short-lived token minted for that specific `User`, or an OAuth-derived session), not an arbitrary string an `ApiClient` can set. At minimum, restrict which `ApiClient`s (and which permission scope) are allowed to set `X-Shipit-User`, and audit/log the underlying `ApiClient` alongside the claimed user for every attributed action.

### Proof of Concept
1. Obtain (or be issued) an `ApiClient` token scoped only to `lock:stack` for a given stack (via `authentication_token`, see `app/models/shipit/api_client.rb`).
2. Send: `POST /api/stacks/:id/lock` with `Authorization: Basic <base64(client_token)>` and header `X-Shipit-User: admin-login`.
3. Observe `Shipit::Stack#lock` is invoked with `current_user` resolved to the `User` record whose `login` matches `admin-login`, attributing the lock action to that admin's identity — even though no proof of that admin's GitHub identity was ever presented.
4. Repeat against `Api::MergeRequestsController#update` or `Api::TasksController#trigger` to attribute a merge request or task/deploy trigger to an arbitrary existing user.

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

**File:** app/controllers/shipit/api/locks_controller.rb (L11-18)
```ruby
      def create
        if stack.locked?
          render(json: { message: 'Already locked' }, status: :conflict)
        else
          stack.lock(params.reason, current_user)
          render_resource(stack)
        end
      end
```

**File:** app/controllers/shipit/api/merge_requests_controller.rb (L17-20)
```ruby
      def update
        merge_request = MergeRequest.request_merge!(stack, params[:id], current_user)
        if merge_request.waiting?
          head(:accepted)
```

**File:** app/controllers/shipit/api/tasks_controller.rb (L20-21)
```ruby
      def trigger
        render_resource(stack.trigger_task(params[:task_name], current_user, env: params.env), status: :accepted)
```
