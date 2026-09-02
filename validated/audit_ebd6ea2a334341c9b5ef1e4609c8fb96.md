### Title
Unauthorized cross-team disclosure of stack `lock_reason` via `MergeStatusController#show` bypassing `authorized?` check - ([File: app/controllers/shipit/merge_status_controller.rb])

### Summary
`MergeStatusController` skips the `force_github_authentication` before_action (which enforces `current_user.authorized?`, i.e., `Shipit.github_teams` membership) for the `show` action, and `#show` only checks `current_user.logged_in?`. Any GitHub user can complete OAuth login through `GithubAuthenticationController#callback` (which sets `session[:user_id]` without any team check) and then query `/merge_status` for a stack belonging to an organization/team they are not authorized for, reading that stack's `lock_reason`.

### Finding Description
The intended binding is: `current_user.authorized?` (team-scoped, checked in `force_github_authentication` at `app/controllers/concerns/shipit/authentication.rb:26`) == gatekeeper for access to any stack's content. `MergeStatusController` breaks this binding for the `show`/`check` actions: [1](#0-0) 

`skip_authentication only: %i[check show]` removes the `authorized?` gate entirely for `show`, and the only remaining guard is `return render('logged_out') unless current_user.logged_in?` — a login check, not a team-membership check.

Root cause: `GithubAuthenticationController#callback` grants *any* GitHub account a valid Shipit session with no team check at all: [2](#0-1) 

The `authorized?` check only happens later, inside `force_github_authentication`: [3](#0-2) 

Since `MergeStatusController#show` explicitly skips this before_action, an attacker who is `logged_in?` but not `authorized?` (not a member of any configured `Shipit.github_teams`) can still resolve an arbitrary stack via the `referrer`/`branch` params and hit the locked-stack render path: [4](#0-3) 

which, when the target stack is locked, renders `locked.html.erb`, embedding `@stack.lock_reason`: [5](#0-4) 

Attacker flow:
1. Attacker completes GitHub OAuth against the Shipit host using their own (unrelated) GitHub account — no team membership required — establishing `session[:user_id]`.
2. Attacker sends `GET /merge_status?referrer=https://github.com/<victim-org>/<victim-repo>/pull/<n>&branch=<branch>`.
3. `stack` resolves a `Stack` row for `<victim-org>/<victim-repo>` regardless of the attacker's team membership (the `stack` lookup has no authorization filter, only repo owner/name/branch matching).
4. `current_user.logged_in?` is true, so the `logged_out` early-return doesn't trigger.
5. If the resolved stack is locked, `stack_status` returns `'locked'` and `locked.html.erb` renders `@stack.lock_reason`, disclosing operator-authored lock text (which can include sensitive operational details, e.g., incident references, credentials pending rotation, security notes, etc.) to a user outside the authorized team.

This bypasses the intended team-scoped authorization boundary that every other engine controller enforces via `force_github_authentication`.

### Impact Explanation
An authenticated-but-unauthorized user (any GitHub account holder who completes OAuth, requiring no privileged secret) can read the `lock_reason` of any stack in the Shipit instance, including stacks belonging to organizations/teams they have no access to. This is a direct escalation past the `Shipit.github_teams` authorization boundary and an unauthenticated (from the authorization perspective) read of stack state, matching the "High" impact category defined in the rules (escalation into `Shipit.github_teams` authorization / unauthenticated read of stack state). It is repeatable against any stack and any organization hosted on the same Shipit instance, so the blast radius spans all tenants sharing the deployment.

### Likelihood Explanation
Preconditions: (1) attacker has any GitHub account and can complete the standard OAuth login flow that Shipit exposes to the public (`GithubAuthenticationController#callback` performs no team check); (2) target stack has a non-blank `lock_reason` and is currently locked; (3) attacker knows or can guess the target org/repo/branch/PR-number (all public, discoverable information on GitHub). No Shipit secrets, tokens, or privileged roles are required — only completing a public OAuth flow, which matches the "unprivileged attacker" definition since the attacker only proves control of their own GitHub identity, not team membership. This makes the attack highly feasible and repeatable at will.

### Recommendation
Do not skip `force_github_authentication`'s `authorized?` check for `show`. Either remove `show` from `skip_authentication`, or replace the `current_user.logged_in?` guard in `#show` with an explicit `current_user.authorized?` check (falling back to the existing `logged_out` template for unauthenticated users and a distinct "unauthorized" response for authenticated-but-unauthorized users), so the `lock_reason` and other stack details are only ever rendered to team-authorized callers.

### Proof of Concept
```ruby
# test/controllers/merge_status_controller_test.rb
test "GET show does not leak lock_reason to a logged-in but unauthorized user" do
  # Simulate a user who is logged_in? but NOT part of Shipit.github_teams
  unauthorized_user = shipit_users(:walrus)
  Shipit::User.any_instance.stubs(:authorized?).returns(false)
  session[:user_id] = unauthorized_user.id

  stack = shipit_stacks(:shipit)
  stack.update!(lock_reason: 'SECRET-INCIDENT-1234', locked_since: Time.now.utc)

  get :show, params: { referrer: 'https://github.com/Shopify/shipit-engine/pull/42', branch: stack.branch }

  # Binding under test: current_user.authorized? (false) should gate stack content,
  # but if it doesn't, the response leaks the lock_reason.
  assert_not unauthorized_user.authorized?
  assert_response :ok
  refute_includes response.body, stack.lock_reason  # currently FAILS: body includes 'SECRET-INCIDENT-1234'
end
```
This demonstrates that despite `current_user.authorized?` being `false`, `MergeStatusController#show` still renders `lock_reason`, confirming the broken binding.

### Citations

**File:** app/controllers/shipit/merge_status_controller.rb (L4-15)
```ruby
  class MergeStatusController < ShipitController
    skip_authentication only: %i[check show]

    etag { cache_seed }
    layout 'merge_status'

    def show
      response.headers['X-Frame-Options'] = 'ALLOWALL'
      response.headers['Vary'] = 'X-Requested-With'

      if stack
        return render('logged_out') unless current_user.logged_in?
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

**File:** app/views/shipit/merge_status/locked.html.erb (L16-19)
```erb
  <span class="status-meta">
    <%= link_to @stack.to_param, stack_url(@stack), target: '_blank', rel: 'noopener' %>
    is <strong>locked</strong> because: <strong><%= auto_link(emojify(@stack.lock_reason), html: { target: '_blank' }) %></strong>
  </span>
```
