I have enough to write up the finding. This is a genuine, concrete issue in `app/controllers/shipit/api/base_controller.rb`'s `identify_user` method, which trusts a client-supplied `X-Shipit-User` header as the identity binding for API-driven deploy/task/merge actions.### Title
API-authenticated deploys/rollbacks/tasks are attributed to (and effectively performed as) any GitHub identity via a spoofable `X-Shipit-User` header - ([File: app/controllers/shipit/api/base_controller.rb])

### Summary
`Shipit::Api::BaseController` authenticates the *caller* using an `ApiClient` bearer token, but derives the *acting user* (`current_user`) from a client-supplied `X-Shipit-User` HTTP header, looked up with no cross-check against the `ApiClient`'s creator or any GitHub-verified identity. Any holder of a valid `ApiClient` token can therefore set this header to the login of an arbitrary existing `Shipit::User` and have deploys, rollbacks, task triggers/aborts, and merge-queue requests recorded and executed as that user.

### Finding Description
Authentication and identity binding are split into two independent, unlinked steps in `app/controllers/shipit/api/base_controller.rb`:

```ruby
before_action :authenticate_api_client
...
def authenticate_api_client
  @current_api_client = if Shipit.disable_api_authentication
                          UnlimitedApiClient.new
                        else
                          BasicAuth.authenticate(request) do |*parts|
                            token = parts.select(&:present?).join('--')
                            ApiClient.authenticate(token)
                          end
                        end
  ...
end

def current_user
  @current_user ||= identify_user || AnonymousUser.new
end

def identify_user
  user_login = request.headers['X-Shipit-User'].presence
  User.where('lower(login) = ?', user_login.downcase).first if user_login
end
``` [1](#0-0) 

`ApiClient.authenticate` only verifies a signed token identifying which `ApiClient` record is calling and what `permissions`/`stack_id` scope it has:
```ruby
def authenticate(token)
  find_by(id: message_verifier.verify(token).to_i)
rescue Shipit::SimpleMessageVerifier::InvalidSignature
end
``` [2](#0-1) 

Nothing binds the verified `ApiClient` (a machine credential, tied to a `creator`) to the `X-Shipit-User` value. This value is then used, unauthenticated, as the acting `User` for security/attribution-relevant operations:

- Triggering a deploy: `stack.trigger_deploy(commit, current_user, ...)` in `app/controllers/shipit/api/deploys_controller.rb:25`, which sets `user_id: user.id` on the deploy [3](#0-2) .
- Triggering/aborting a task: `stack.trigger_task(params[:task_name], current_user, ...)` and `task.abort!(aborted_by: current_user, ...)` in `app/controllers/shipit/api/tasks_controller.rb:20-31`, which sets `user_id`/`aborted_by_id` [4](#0-3) [5](#0-4) .
- Rollback/abort-into-rollback: `deploy.trigger_rollback(current_user, ...)` and `active_task.abort!(aborted_by: current_user, ...)` in `app/controllers/shipit/api/rollbacks_controller.rb:25-28`.
- Merge queue requests: `MergeRequest.request_merge!(stack, params[:id], current_user)` in `app/controllers/shipit/api/merge_requests_controller.rb:18`, which stores `merge_requested_by: user` [6](#0-5) .

Downstream, `TaskCommands#env` derives `SHIPIT_USER`, `EMAIL`, `GIT_COMMITTER_NAME`, `GIT_COMMITTER_EMAIL` directly from `@task.author`/`@task.user` [7](#0-6) , meaning the spoofed identity propagates into the deploy script's environment and into git commit metadata for any deploy actions that commit as the "deploying user."

This is exactly the binding-break pattern in scope: the credential that is cryptographically **authenticated** (the `ApiClient` token / its `creator`) is not the same as the **identity `User` bound to the resulting action** (`current_user` from `X-Shipit-User`). Unlike the human web flow, where `current_user` is set only via the signed OAuth session (`session[:user_id]` populated exclusively in `GithubAuthenticationController#sign_in_github` after a verified GitHub OAuth callback) [8](#0-7) , the API path lets the already-authenticated caller freely declare who performed the action.

### Impact Explanation
Any party possessing a valid `ApiClient` token (which can be scoped to `deploy:stack` only, with no requirement of being a privileged human account) can:
- Attribute deploys, rollbacks, and task executions to any other `Shipit::User` in the system (e.g., an administrator or a user with elevated trust for audit/approval purposes), undermining audit trails used to decide "who deployed this" and "who approved this merge."
- Inject an arbitrary chosen `SHIPIT_USER`/`GIT_COMMITTER_NAME`/`GIT_COMMITTER_EMAIL` into the environment of deploy scripts and into git commits pushed by Shipit, since these are derived from the spoofed user, not from any verified identity.
- Falsify `merge_requested_by` for merge-queue entries.

This matches the report's "identity/authorization binding used for a security-relevant decision does not cover the actual attacker-controlled field" bug class, mapped here onto "GitHub identity vs. the `User` bound to the session" (Rule 4's listed binding), and rises to the level of an unauthorized action performed under a false identity — the closest in-scope category is escalation/impersonation feeding an unauthorized deploy record and falsified authorization trail. It does not, by itself, escalate the `ApiClient`'s own permission scope (permissions/stack scoping are still enforced by `require_permission!`), so this is best framed as an identity-spoofing/attribution vulnerability with downstream trust impact rather than pure privilege escalation.

### Likelihood Explanation
High for anyone who already possesses a valid `ApiClient` token: the header is a simple unauthenticated HTTP header with no signature or verification tying it to the `ApiClient`'s `creator`, and it is honored unconditionally whenever present, defaulting only to `AnonymousUser` when absent. Any script or third-party integration granted an API token (e.g., CI system with `deploy:stack` permission) can trivially set this header to any existing login.

### Recommendation
Do not derive `current_user` from an unauthenticated, client-supplied header. Bind the acting user either to the `ApiClient#creator` association, or require that `X-Shipit-User` be cross-validated against a scope/allow-list configured on the `ApiClient` record, or removed entirely in favor of attributing API-driven actions to the `ApiClient` itself (with a dedicated `AnonymousUser`/service-account representation) so audit trails cannot be forged.

### Proof of Concept
1. Obtain (or be issued) any valid `ApiClient` token scoped only to `deploy:stack` (e.g., a CI integration token), via Basic Auth as shown in `test/controllers/api/tasks_controller_test.rb` / `test/controllers/api/ccmenu_controller_test.rb` patterns [9](#0-8) .
2. Send:
```
POST /api/stacks/:stack_id/deploys
Authorization: Basic <api_client_token>
X-Shipit-User: some-admin-login
{"sha": "<sha>"}
```
3. `identify_user` resolves `current_user` to the `User` with `login == "some-admin-login"` [10](#0-9) .
4. `stack.trigger_deploy(commit, current_user, ...)` creates the deploy with `user_id` set to that admin's `User#id` [3](#0-2) , and `TaskCommands#env` sets `SHIPIT_USER`/`GIT_COMMITTER_NAME`/`GIT_COMMITTER_EMAIL` to that admin's identity [7](#0-6)  — the deploy is now falsely recorded and executed as performed by "some-admin-login," with no verification that the caller controls that identity.

### Citations

**File:** app/controllers/shipit/api/base_controller.rb (L24-72)
```ruby
      before_action :authenticate_api_client

      def index
        render(json: { stacks_url: api_stacks_url })
      end

      private

      module BasicAuth
        # Workaround for https://github.com/rails/rails/pull/44610
        extend ActionController::HttpAuthentication::Basic
        extend self

        private

        def basic_credentials?(request)
          request.authorization.present? && (auth_scheme(request).downcase == "basic")
        end
      end

      def namespace_for_serializer
        nil
      end

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

**File:** app/models/shipit/api_client.rb (L23-27)
```ruby
    class << self
      def authenticate(token)
        find_by(id: message_verifier.verify(token).to_i)
      rescue Shipit::SimpleMessageVerifier::InvalidSignature
      end
```

**File:** app/models/shipit/stack.rb (L139-159)
```ruby
    def trigger_task(definition_id, user, env: nil, force: false)
      definition = find_task_definition(definition_id)
      env = env.to_h

      definition.variables_with_defaults.each do |variable|
        env[variable.name] ||= variable.default
      end

      commit = last_deployed_commit.presence || commits.first
      task = tasks.create(
        user_id: user.id,
        definition:,
        until_commit_id: commit.id,
        since_commit_id: commit.id,
        env: definition.filter_envs(env),
        allow_concurrency: definition.allow_concurrency? || force,
        ignored_safeties: force
      )
      task.enqueue
      task
    end
```

**File:** app/models/shipit/stack.rb (L161-172)
```ruby
    def build_deploy(until_commit, user, env: nil, force: false, allow_concurrency: force)
      since_commit = last_deployed_commit.presence || commits.first
      deploys.build(
        user_id: user.id,
        until_commit:,
        since_commit:,
        env: filter_deploy_envs(env.to_h),
        allow_concurrency:,
        ignored_safeties: force || !until_commit.deployable?,
        max_retries: retries_on_deploy
      )
    end
```

**File:** app/models/shipit/task.rb (L356-360)
```ruby
    def abort!(aborted_by:, rollback_once_aborted: false, rollback_once_aborted_to: nil)
      update!(
        rollback_once_aborted:,
        rollback_once_aborted_to:,
        aborted_by_id: aborted_by.id
```

**File:** app/models/shipit/merge_request.rb (L126-143)
```ruby
    def self.request_merge!(stack, number, user)
      now = Time.now.utc
      merge_request = begin
        create_with(
          merge_requested_at: now,
          merge_requested_by: user.presence
        ).find_or_create_by!(
          stack:,
          number:
        )
      rescue ActiveRecord::RecordNotUnique
        retry
      end
      merge_request.update!(merge_requested_by: user.presence)
      merge_request.retry! if merge_request.rejected? || merge_request.canceled? || merge_request.revalidating?
      merge_request.schedule_refresh!
      merge_request
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

**File:** app/controllers/shipit/github_authentication_controller.rb (L30-34)
```ruby
    def sign_in_github(auth)
      user = User.find_or_create_from_github(auth.extra.raw_info)
      user.update(github_access_token: auth.credentials.token)
      user.id
    end
```

**File:** test/controllers/api/tasks_controller_test.rb (L35-46)
```ruby
      test "#trigger triggers a custom task" do
        post :trigger, params: { stack_id: @stack.to_param, task_name: 'restart' }
        assert_response :accepted
        assert_json 'type', 'task'
        assert_json 'status', 'pending'

        expected_env = {
          "FOO" => "1",
          "BAR" => "0"
        }
        assert_equal expected_env, Shipit::Task.last.env
      end
```
