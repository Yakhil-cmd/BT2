### Title
Unauthenticated `X-Shipit-User` header allows identity forgery for task/deploy authorship - ([File: app/controllers/shipit/api/base_controller.rb])

### Summary
`Api::BaseController#identify_user` sets `current_user` purely from the client-supplied `X-Shipit-User` request header, looking up any `User` by login with no verification that the caller actually controls that GitHub identity. Any holder of a valid `ApiClient` token with `deploy:stack` permission can impersonate an arbitrary Shipit user for task/deploy authorship.

### Finding Description
The broken binding is: `current_user == the GitHub identity that authenticated this request`. In practice, `identify_user` implements `current_user = User.where('lower(login) = ?', request.headers['X-Shipit-User'].downcase).first`, which is fully attacker-controlled and has no relationship to the credential that authenticated the request [1](#0-0) .

`authenticate_api_client` only verifies that the `Authorization: Basic` token corresponds to a real `ApiClient` via `ApiClient.authenticate` / `SimpleMessageVerifier`; it does not tie the client to a specific user, nor cross-check `X-Shipit-User` against `ApiClient#creator` [2](#0-1) [3](#0-2) . `ApiClient#check_permissions!` only enforces coarse `operation:scope` strings (e.g. `deploy:stack`) from a fixed list, with no user identity component [4](#0-3) .

`Api::TasksController#trigger` passes `current_user` directly into `stack.trigger_task`, guarded only by `require_permission :deploy, :stack` [5](#0-4) . The resulting `Task`'s `user`/`author` fields are then consumed by `TaskCommands#env`, which injects `SHIPIT_USER`, `EMAIL`, `GIT_COMMITTER_NAME`, and `GIT_COMMITTER_EMAIL` into the environment that reaches `Command`/`PTY.spawn` [6](#0-5) .

Exploit flow: attacker holds a low-privilege `ApiClient` token scoped to one stack with `deploy:stack` permission (e.g., a CI token). They send `POST /api/stacks/:owner/:repo/:env/tasks` with `Authorization: Basic <their token>` and header `X-Shipit-User: victim_login`. `identify_user` resolves `victim_login`'s `User` record with zero proof of control over that identity, and the created `Task`/`Deploy` is attributed to the victim, with the victim's name/email injected into commit/committer environment variables on the deploy host.

Existing guards (`authenticate_api_client`, `require_permission!`, `EnvironmentVariables#permit`) validate the *token* and the *env whitelist*, but none of them validate the *user* claim in `X-Shipit-User`, so the divergence is real and unmitigated.

### Impact Explanation
The attacker can forge the authorship of tasks and deploys against any stack they have `deploy:stack` permission for, injecting an arbitrary victim's login/name/email into `GIT_COMMITTER_NAME`/`GIT_COMMITTER_EMAIL`/`SHIPIT_USER` environment variables that reach the deploy host's `PTY.spawn`-executed commands, and permanently misattributing the action in Shipit's audit trail (`Task#user`, `Task#author`). This satisfies the "unauthorized deploy" / "misattribution enabling unauthorized action" Critical impact category. The attack is repeatable for every request and works against any stack the attacker's token is scoped to; it does not, by itself, escalate to a different stack/tenant beyond what the token's `stack_id` already permits, but it does break the identity-authorization binding within that scope.

### Likelihood Explanation
Requires the attacker to already hold a valid `ApiClient` authentication token with `deploy:stack` permission on some stack — this is a real-world scenario (e.g., leaked or intentionally scoped low-privilege CI/automation tokens are common in Shipit deployments, per the question's precondition). No GitHub secrets, session, or webhook signature are needed; only an existing API token and a single unauthenticated header. Feasibility is high once a token is obtained, and the exploit is trivially repeatable.

### Recommendation
Do not trust `X-Shipit-User` as an unauthenticated identity claim. Either (a) bind `current_user` to `current_api_client.creator` and drop the header entirely, or (b) require that the `User` named in `X-Shipit-User` be validated against a scoped, per-user credential (e.g., only trust the header when `current_api_client.creator&.login == user_login`, or when the API client is explicitly associated with that user), rejecting the request otherwise.

### Proof of Concept
```ruby
# test/controllers/api/tasks_controller_test.rb
test "#trigger does not let the caller impersonate an arbitrary user via X-Shipit-User" do
  attacker_client = shipit_api_clients(:low_privilege) # deploy:stack scoped to @stack only
  victim = shipit_users(:walrus)                       # never authenticated this request
  authenticate!(attacker_client)

  request.headers['X-Shipit-User'] = victim.login
  post :trigger, params: { stack_id: @stack.to_param, task_name: 'restart' }

  task = Shipit::Task.last
  # Binding under test: current_user (task author) must equal the identity
  # that actually authenticated the request (attacker_client.creator),
  # not an arbitrary header value.
  assert_not_equal victim, task.user
  assert_equal attacker_client.creator, task.user
end
```
This currently fails: `task.user`/`task.author` is set to `victim`, proving `current_user` was forged from the unauthenticated `X-Shipit-User` header rather than bound to the authenticating `ApiClient`'s creator.

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

**File:** app/models/shipit/api_client.rb (L4-12)
```ruby
  class ApiClient < Record
    InsufficientPermission = Class.new(StandardError)

    belongs_to :creator, class_name: 'User'
    belongs_to :stack, optional: true

    validates :creator, :name, presence: true

    serialize :permissions, coder: Shipit.serialized_column(:permissions, type: Array)
```

**File:** app/models/shipit/api_client.rb (L13-45)
```ruby
    PERMISSIONS = %w[
      read:stack
      write:stack
      deploy:stack
      lock:stack
      read:hook
      write:hook
    ].freeze
    validates :permissions, subset: { of: PERMISSIONS }

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

    def check_permissions!(operation, scope)
      required_permission = "#{operation}:#{scope}"
      unless permissions.include?(required_permission)
        raise InsufficientPermission, "This operation requires the `#{required_permission}` permission"
      end

      true
    end
```

**File:** app/controllers/shipit/api/tasks_controller.rb (L6-26)
```ruby
      require_permission :read, :stack
      require_permission :deploy, :stack, only: %i[trigger abort]

      def index
        render_resources(stack.tasks)
      end

      def show
        render_resource(task)
      end

      params do
        accepts :env, Hash, default: {}
      end
      def trigger
        render_resource(stack.trigger_task(params[:task_name], current_user, env: params.env), status: :accepted)
      rescue Shipit::Task::ConcurrentTaskRunning
        render(status: :conflict, json: {
                 message: 'A task is already running.'
               })
      end
```

**File:** lib/shipit/task_commands.rb (L33-48)
```ruby
    def env
      super
        .merge(@stack.env)
        .merge(
          'SHIPIT_USER' => "#{@task.author.login} (#{normalized_author_name}) via Shipit",
          'EMAIL' => @task.author.email,
          'BUNDLE_PATH' => Rails.root.join('data', 'bundler').to_s,
          'SHIPIT_LINK' => @task.permalink,
          'TASK_ID' => @task.id.to_s,
          'IGNORED_SAFETIES' => @task.ignored_safeties? ? '1' : '0',
          'GIT_COMMITTER_NAME' => @task.user&.name || Shipit.committer_name,
          'GIT_COMMITTER_EMAIL' => @task.user&.email || Shipit.committer_email
        )
        .merge(deploy_spec.machine_env)
        .merge(@task.env)
    end
```
