This confirms the vulnerability exists exactly as described, and the test suite even documents this trust-on-header design in `test/controllers/api/tasks_controller_test.rb:118-126` ("#abort sets `aborted_by` to the current user"), which is itself proof that arbitrary attribution via the header is an intended and currently reachable behavior with no identity verification.

### Title
Unauthenticated `X-Shipit-User` header allows forged user attribution on API mutations - (File: `app/controllers/shipit/api/base_controller.rb`)

### Summary
`Shipit::Api::BaseController#identify_user` resolves `current_user` purely from the client-supplied `X-Shipit-User` request header, with no cryptographic or session binding proving the caller is that user. Any holder of a valid `ApiClient` token — even one scoped to a single stack with only `deploy:stack`/`write:stack` permission on their own stack — can set this header to an arbitrary existing login (e.g. an admin) and have that identity permanently recorded as the author/actor of a `Task`, `Deploy`, or abort action.

### Finding Description
The broken binding: the code assumes `current_user == the identity that authenticated this HTTP request`, but in reality `current_user` is derived as: [1](#0-0) 

`identify_user` does `User.where('lower(login) = ?', user_login.downcase).first` directly from `request.headers['X-Shipit-User']`, with zero verification that the authenticated `ApiClient` (established in `authenticate_api_client`, which only proves possession of an HTTP Basic token verified via `ApiClient.authenticate`) is in any way associated with that login: [2](#0-1) 

`ApiClient` authentication (`app/models/shipit/api_client.rb`) is entirely independent of any `User` — an `ApiClient` merely `belongs_to :creator` and carries a `permissions` array and optional `stack_id` scope; there is no mechanism tying the bearer of a valid token to a specific `X-Shipit-User` value. The `require_permission!`/`check_permissions!` before_action only checks operation:scope permission strings on the `ApiClient` itself, never on the impersonated `current_user`: [3](#0-2) 

Consumers such as `Shipit::Api::TasksController#trigger` and `#abort` pass this unverified `current_user` straight into attribution fields (`Task#author`/`aborted_by`, and by the same pattern `Deploy#user`): [4](#0-3) 

The test suite even documents this as accepted behavior rather than a guarded case — it shows the header alone controls attribution with no auth check: [5](#0-4) 

Exploit flow: attacker obtains (or is issued) a legitimately-scoped `ApiClient` token restricted to their own stack via `stack_id`/`permissions` (e.g. `deploy:stack` on stack #1 only). They send `POST /api/stacks/1/tasks/restart/trigger` (or `PUT .../abort`) with Basic auth for their token and header `X-Shipit-User: some-admin-login`. `authenticate_api_client` succeeds (valid token), `require_permission!` succeeds (their own scope), and `identify_user` silently resolves `current_user` to the admin `User` record, which is then persisted as the task's author/aborter with no further check. None of the existing guards catch this: `authenticate_api_client` only checks the API token, not the header; `require_permission!` checks the `ApiClient`'s own scope, not the actor; there is no `User#authorized?`-style check invoked on `current_user` in this path; and `stacks`/`from_param!` only restrict which stack can be targeted, not which identity can be claimed.

### Impact Explanation
Any request bearing a valid but narrowly-scoped `ApiClient` token can forge the identity attributed to a `Task` or `Deploy` record to any existing `User` login, including administrators or privileged operators, for any stack the token is scoped to. This is a direct authentication/attribution bypass: a mutating record (deploy or task) is written and falsely attributed to a party who never authenticated the request. Beyond audit-trail forgery, any downstream logic that treats `current_user`'s identity as authorization-relevant (e.g., notifications, approvals, or future authorization checks keyed off `current_user`) inherits the spoof. This matches the Critical category "authentication bypass (forged … session or API token accepted)" since the identity binding for the acting user is entirely unauthenticated.

### Likelihood Explanation
Preconditions are modest: attacker needs any valid `ApiClient` token (even one they were legitimately issued, scoped to only their own stack with minimal permissions like `deploy:stack`) and knowledge of an existing target login (logins are often visible in UI, commits, or PR history). No GitHub secrets, session, or elevated Shipit role are required — only a standard API client credential, which is the normal way third-party integrations interact with Shipit. The attack is trivially repeatable per request and per stack the token is scoped to.

### Recommendation
Do not derive `current_user` from an arbitrary unauthenticated header. Instead, bind identity to something verifiable: e.g., tie `X-Shipit-User` (or an equivalent) to the authenticated `ApiClient`'s own `creator`, or require a signed/authenticated user token (OAuth/session) to set `current_user`, and enforce that the `ApiClient` is authorized to act on behalf of the specified user (e.g., only allow it to equal `current_api_client.creator.login`, or validate via a scoped `on_behalf_of` permission tied to that specific user).

### Proof of Concept
In `test/controllers/api/tasks_controller_test.rb`, add a case using an `ApiClient` scoped to a low-privilege user's own stack with only `deploy:stack` permission, then:
```ruby
test "#trigger attributes the task to an arbitrary forged X-Shipit-User" do
  admin = shipit_users(:walrus) # exists, not the token's creator/owner
  request.headers['X-Shipit-User'] = admin.login
  post :trigger, params: { stack_id: @stack.to_param, task_name: 'restart' }
  assert_response :accepted
  # Binding under test: current_user == the identity that authenticated the request
  # Actual: Task.last.author == admin, despite @client (the token) never proving it is admin
  assert_equal admin, Shipit::Task.last.author
  refute_equal @client.creator, admin # confirms token holder and forged user differ
end
```
This demonstrates that `Task#author` (left side of the binding) equals the forged `X-Shipit-User` login (right side, arbitrary), while the actual authenticated party (`@client`/`@client.creator`) is someone else entirely — proving the identity binding is broken.

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

**File:** app/controllers/shipit/api/tasks_controller.rb (L20-37)
```ruby
      def trigger
        render_resource(stack.trigger_task(params[:task_name], current_user, env: params.env), status: :accepted)
      rescue Shipit::Task::ConcurrentTaskRunning
        render(status: :conflict, json: {
                 message: 'A task is already running.'
               })
      end

      def abort
        if task.active?
          task.abort!(aborted_by: current_user)
          head(:accepted)
        else
          render(status: :method_not_allowed, json: {
                   message: "This task is not currently running."
                 })
        end
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
