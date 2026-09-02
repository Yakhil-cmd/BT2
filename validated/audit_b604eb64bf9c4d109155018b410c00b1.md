### Title
`show` bypasses `Shipit.github_teams` authorization, allowing any logged-in user to read `stack_status` for arbitrary stacks - ([File: app/controllers/shipit/merge_status_controller.rb])

### Summary
`MergeStatusController` declares `skip_authentication only: %i[check show]`, which skips the `force_github_authentication` `before_action` for the `show` action [1](#0-0) . Since `force_github_authentication` is the only place `current_user.authorized?` (team membership) is enforced [2](#0-1) , and `show` itself only checks `current_user.logged_in?` [3](#0-2) , any authenticated Shipit user — regardless of `Shipit.github_teams` membership — can retrieve `stack_status` for any stack.

### Finding Description
The claimed binding is: `current_user.authorized?` == `true` for every caller that receives `stack_status` from `show`. Tracing the code shows this binding does **not** hold.

- `force_github_authentication` is the sole enforcement point of team-based authorization: it renders `403 Forbidden` unless `current_user.authorized?` is true, where `authorized?` checks team membership against `Shipit.github_teams` [4](#0-3)  and [5](#0-4) .
- `MergeStatusController` explicitly skips this `before_action` for `show` (and `check`) via `skip_authentication only: %i[check show]` [6](#0-5) .
- Inside `show`, the only gate is `return render('logged_out') unless current_user.logged_in?` [7](#0-6) . `User#logged_in?` unconditionally returns `true` for any persisted `User` record found via `session[:user_id]`, with no team check [8](#0-7) .
- `stack` is resolved either via `params[:stack_id]` through `Stack.from_param!` (arbitrary stack lookup by id/param, no ownership scoping) or via referrer-derived repo/branch lookup — neither path checks the caller's authorization [9](#0-8) .
- `stack_status` calls `stack.merge_status(...)`, rendered directly to the logged-in caller [10](#0-9)  and [11](#0-10) .

Exploit flow: an attacker who has completed a Shipit OAuth login once (obtaining a valid `session[:user_id]` for a `User` row that exists but belongs to no `Shipit.github_teams`-mapped team) issues `GET /merge_status/:stack_id` (or with a `referrer` param pointing at any repo/branch). Because `force_github_authentication` never runs on `show`, the `authorized?` team check is never evaluated, and the attacker receives full `stack_status` for a stack outside the teams they belong to. This differs from every other engine action, where `force_github_authentication` would return the 403 "You must be a member of ... to access this application" message instead.

Note: the attacker model in this audit is explicitly "unprivileged, no Shipit session." Reaching this bug requires a valid `session[:user_id]` (i.e., completing GitHub OAuth login), which is a precondition beyond a pure unauthenticated attacker, but is far weaker than the intended `Shipit.github_teams` membership requirement — the actual security boundary this code is designed to enforce.

### Impact Explanation
Any logged-in-but-unauthorized Shipit user can read merge/CI/deploy status information (`stack_status`) for stacks belonging to teams/repositories they are not authorized to access, bypassing the `Shipit.github_teams` boundary that `force_github_authentication` is supposed to enforce everywhere else in the engine. This is repeatable against arbitrary stacks by varying `stack_id` or `referrer`, and matches the "High" category: escalation into `Shipit.github_teams` authorization / unauthorized read of stack state.

### Likelihood Explanation
Preconditions: the attacker must have logged in via GitHub OAuth at least once (obtaining a `Shipit::User` row and a valid session), which the described attacker model does not explicitly grant but is a low-cost action (any GitHub account can complete OAuth if the Shipit instance allows public GitHub login, which is the common configuration since `Shipit.github_teams` is exactly the mechanism meant to gate further access after login). Once logged in, exploitation is a single unauthenticated-style GET request with no other secrets required, and is trivially repeatable across all stacks.

### Recommendation
Remove `show` from `skip_authentication` (or otherwise invoke `force_github_authentication`/`current_user.authorized?` explicitly at the top of `show`) so that team-membership authorization is enforced identically to every other controller action, only leaving the `logged_in?` vs `render('logged_out')` behavior for the truly-unauthenticated case.

### Proof of Concept
```ruby
# test/controllers/shipit/merge_status_controller_test.rb
test "#show does not leak stack_status to a logged-in user outside Shipit.github_teams" do
  stack = shipit_stacks(:shipit)
  unauthorized_user = shipit_users(:walrus) # fixture user with no team membership in Shipit.github_teams
  session[:user_id] = unauthorized_user.id

  Shipit.stubs(:github_teams).returns([stub(id: 999, handle: 'some-team')]) # user not in this team
  assert_not unauthorized_user.authorized?

  get :show, params: { stack_id: stack.to_param }

  # Binding under test: current_user.authorized? == true is required for stack_status to be rendered.
  # Expected (secure) behavior: 403 forbidden body, same as force_github_authentication elsewhere.
  assert_response :forbidden
  assert_match(/You must be a member of/, response.body)

  # Actual (vulnerable) behavior observed today: 200 with stack_status content instead.
end
```

### Citations

**File:** app/controllers/shipit/merge_status_controller.rb (L4-5)
```ruby
  class MergeStatusController < ShipitController
    skip_authentication only: %i[check show]
```

**File:** app/controllers/shipit/merge_status_controller.rb (L14-19)
```ruby
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

**File:** app/models/shipit/user.rb (L76-78)
```ruby
    def logged_in?
      true
    end
```

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```
