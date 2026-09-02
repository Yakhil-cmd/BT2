This confirms the callback controller does not check team membership before creating a session; any GitHub OAuth user becomes a valid, logged-in `session[:user_id]`, and `User#authorized?` is only enforced inside `force_github_authentication` [1](#0-0) [2](#0-1) . `MergeStatusController` explicitly skips that before_action for `:show` and `:check`, and `#show` only gates on `current_user.logged_in?`, never on `authorized?`, before rendering `stack_status` (which calls `stack.merge_status`) [3](#0-2) [4](#0-3) . `User#logged_in?` unconditionally returns `true` and is unrelated to team membership, while `authorized?` is the only method that checks `Shipit.github_teams` [5](#0-4) .

### Title
Unauthorized read of stack merge status via MergeStatusController#show skipping team authorization - (File: app/controllers/shipit/merge_status_controller.rb)

### Summary
`MergeStatusController` skips `force_github_authentication` for `:show` (and `:check`), so `current_user.authorized?` (the `Shipit.github_teams` membership check) is never evaluated. The action only requires `current_user.logged_in?`, which is `true` for any authenticated GitHub user regardless of team membership, allowing any GitHub-authenticated Shipit user to read another organization's/repo's stack merge status.

### Finding Description
The broken binding: the intended authorization invariant is `response_rendered => current_user.authorized?`, but the actual code path enforces only `response_rendered => current_user.logged_in?`, and `logged_in? != authorized?` for a user who is not in `Shipit.github_teams`.

Path: `GithubAuthenticationController#callback` creates/loads a `User` from any GitHub OAuth identity and sets `session[:user_id]` unconditionally, with no team check [1](#0-0) . `Authentication#force_github_authentication` is the sole place `current_user.authorized?` is invoked, rendering a 403 for non-team members [2](#0-1) . `MergeStatusController` declares `skip_authentication only: %i[check show]`, removing that before_action for `#show` [6](#0-5) . `#show` then only checks `current_user.logged_in?` (always `true` for a persisted `User`, per `User#logged_in?`) before rendering `stack_status`, i.e. `stack.merge_status(...)` [7](#0-6) [8](#0-7) . `authorized?` is never called anywhere in this controller.

Attacker request: complete OAuth as any GitHub user (no team membership required), then `GET /merge_status?referrer=https://github.com/other-org/other-repo/pull/7&branch=main`. The `stack` lookup resolves purely from `referrer`/`branch` params against `Repository`/`Stack` records, with no ownership or team check tying the resolved stack to the requesting user [9](#0-8) .

Existing guards fail to prevent this because they are simply absent from this path: `skip_authentication` deliberately removes `force_github_authentication` for `:show`/`:check`, and no other before_action or inline check calls `authorized?` in `MergeStatusController`.

### Impact Explanation
Any logged-in-but-unauthorized GitHub user (not in `Shipit.github_teams`) can read merge-queue/stack status (e.g. "Ready to ship!", checks, lock state) for any stack whose owner/repo/branch they can guess or discover, including stacks belonging to organizations they have no relationship with. This is an unauthenticated-relative-to-`Shipit.github_teams` read of stack state — matching the High-severity category "escalation into `Shipit.github_teams` authorization, unauthenticated read of stack state." It is repeatable for any stack/repo/branch combination and does not require any secret.

### Likelihood Explanation
Preconditions: `Shipit.github_teams` configured non-empty (a normal production configuration for access control), and the attacker only needs a GitHub account able to complete OAuth against the Shipit instance (no org/team membership, no invite). Cost is trivial: one OAuth login plus one GET request with a crafted `referrer`/`branch`. This is highly feasible and fully repeatable against any stack.

### Recommendation
Add `authorize!`/`current_user.authorized?` enforcement inside `MergeStatusController#show` (and `#check`) instead of relying solely on `logged_in?`, or remove `:show`/`:check` from `skip_authentication` and instead selectively skip only the redirect-for-anonymous behavior while still calling the `authorized?` check for logged-in users.

### Proof of Concept
```ruby
# test/controllers/merge_status_controller_test.rb
test "#show renders stack status for a logged-in but unauthorized user" do
  Shipit.github_teams = [stub(id: 999, handle: 'core-team')] # non-empty teams
  stack = shipit_stacks(:shipit)
  unauthorized_user = shipit_users(:walrus) # not a member of any Shipit.github_teams
  assert_not unauthorized_user.authorized?

  session[:user_id] = unauthorized_user.id

  get :show, params: {
    referrer: "https://github.com/#{stack.repository.owner}/#{stack.repository.name}/pull/7",
    branch: stack.branch
  }

  assert_response :success
  assert_match(/Ready to ship!/, response.body) # or another stack_status string
end
```
Binding assertions: before — `unauthorized_user.authorized? == false`; after — `response.status == 200` and `response.body` contains `stack.merge_status` content, demonstrating `authorized?` was never consulted despite being `false`.

### Citations

**File:** app/controllers/shipit/github_authentication_controller.rb (L7-21)
```ruby
    def callback
      return_url = request.env['omniauth.origin'] || root_path
      auth = request.env['omniauth.auth']

      return render('failed', layout: false) if auth.blank?

      session[:user_id] = sign_in_github(auth)

      # We need to set this so that the /events and /sidekiq endpoint
      # which leverage `UserRequiredMiddleware` will recognize the user
      # is authenticated.
      session[:authenticated] = true

      redirect_to(return_url)
    end
```

**File:** app/controllers/concerns/shipit/authentication.rb (L20-34)
```ruby
    def force_github_authentication
      if current_user.logged_in? && current_user.requires_fresh_login?
        Rails.logger.warn("User #{current_user.id} requires a fresh login, logging out...")
        reset_session
        redirect_to(Shipit::Engine.routes.url_helpers.github_authentication_path(origin: request.original_url))
      elsif Shipit.authentication_disabled? || current_user.logged_in?
        unless current_user.authorized?
          team_handles = Shipit.github_teams.map(&:handle)
          team_list = team_handles.to_sentence(two_words_connector: ' or ', last_word_connector: ', or ')
          render(plain: "You must be a member of #{team_list} to access this application.", status: :forbidden)
        end
      else
        redirect_to(Shipit::Engine.routes.url_helpers.github_authentication_path(origin: request.original_url))
      end
    end
```

**File:** app/controllers/shipit/merge_status_controller.rb (L5-19)
```ruby
    skip_authentication only: %i[check show]

    etag { cache_seed }
    layout 'merge_status'

    def show
      response.headers['X-Frame-Options'] = 'ALLOWALL'
      response.headers['Vary'] = 'X-Requested-With'

      if stack
        return render('logged_out') unless current_user.logged_in?

        if stale?(last_modified: [stack.updated_at, merge_request.updated_at].max, template: false)
          render(stack_status, layout: !request.xhr?)
        end
```

**File:** app/controllers/shipit/merge_status_controller.rb (L58-60)
```ruby
    def stack_status
      @stack_status ||= stack.merge_status(backlog_leniency_factor: 1.0)
    end
```

**File:** app/controllers/shipit/merge_status_controller.rb (L62-81)
```ruby
    def stack
      @stack ||= if params[:stack_id]
                   Stack.from_param!(params[:stack_id])
                 else
                   # Null ordering is inconsistent across DBMS's, this case statement is ugly but supported universally
                   scope = Stack.order(Arel.sql('CASE WHEN locked_since IS NULL THEN 1 ELSE 0 END, locked_since'))
                                .order(merge_queue_enabled: :desc, id: :asc).includes(:repository).where(
                                  repositories: {
                                    owner: referrer_parser.repo_owner,
                                    name: referrer_parser.repo_name
                                  }
                                )
                   scope = if params[:branch]
                             scope.where(branch: params[:branch])
                           else
                             scope.where(environment: 'production')
                           end
                   scope.first
                 end
    end
```

**File:** app/models/shipit/user.rb (L76-82)
```ruby
    def logged_in?
      true
    end

    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```
