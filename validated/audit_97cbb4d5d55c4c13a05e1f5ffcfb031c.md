Confirmed. `Shipit::MergeStatusController` declares `skip_authentication only: %i[check show]` [1](#0-0) , which skips the `force_github_authentication` before_action entirely for `:show` [2](#0-1) . `force_github_authentication` is the only place in the engine that calls `current_user.authorized?` (the `Shipit.github_teams` membership check) [3](#0-2) . The `show` action itself only gates on `current_user.logged_in?`, never on `authorized?` [4](#0-3) , and `User#authorized?` is defined but simply never invoked on this path [5](#0-4) . The `stack` lookup resolves purely from `params[:referrer]`/`params[:branch]` against any `Repository` in the database, with no ownership/team scoping [6](#0-5) , and `stack_status` renders `stack.merge_status` (e.g. "Ready to ship!") into the response body [7](#0-6) .

### Title
`MergeStatusController#show`/`#check` skip `authorized?`, allowing any logged-in-but-non-team user to read cross-org stack merge status - (File: `app/controllers/shipit/merge_status_controller.rb`)

### Summary
`MergeStatusController` opts `:show` and `:check` out of `force_github_authentication` via `skip_authentication only: %i[check show]`, which is the only place `User#authorized?` (the `Shipit.github_teams` gate) is enforced. As a result, any GitHub user who completes OAuth and obtains a Shipit session — even one who is not a member of any configured `Shipit.github_teams` — can read `stack.merge_status` (locked/backlogged/success/failure) for any repository/branch tracked by the Shipit instance, not just ones belonging to their team.

### Finding Description
The broken binding: the codebase's intended invariant is `current_user.logged_in? && current_user.authorized?` gates read access to stack data (enforced elsewhere via `force_github_authentication`, as seen in `StacksController`/`RepositoriesController` returning 403 "You must be a member of ... to access this application" for non-team users) [8](#0-7) . For `MergeStatusController#show`, this invariant is broken: only `current_user.logged_in?` is checked [9](#0-8) , because `skip_authentication only: %i[check show]` removes the `before_action` that would have called `authorized?` [10](#0-9) , [3](#0-2) .

Attack: attacker completes `GithubAuthenticationController#callback` with any GitHub account (unrelated to any Shipit team), establishing `session[:user_id]` for a `User` whose `authorized?` is `false` (per `User#authorized? = Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams...).exists?`) [5](#0-4) . They then `GET /merge_status?referrer=https://github.com/other-org/other-repo/pull/7&branch=main`. The `stack` resolver matches `Repository` by `owner`/`name` parsed from `referrer` and `branch` param, with no scoping to the current user's teams or repos [6](#0-5) . Because `authorized?` is never called on this path, the response renders the stack's merge status template (e.g. "Ready to ship!"/"locked"/"backlogged") regardless of team membership.

### Impact Explanation
An attacker who is any logged-in GitHub user (not necessarily a team member) can enumerate/read the merge/deploy-readiness state (locked, backlogged, failing, ready-to-ship) of any stack tracked by the Shipit instance across any organization, simply by supplying a `referrer` URL and `branch`. This is a repeatable, unauthenticated-with-respect-to-team-membership read of stack state, matching the "escalation into `Shipit.github_teams` authorization, unauthenticated read of stack state" High-impact category. It does not permit writes, deploys, or credential exposure — it is confined to `stack.merge_status`, `merge_request` waiting/status info, and stack lock reason text rendered in the partials [11](#0-10) .

### Likelihood Explanation
Low attacker cost: OAuth login with any GitHub account is a normal, unprivileged flow already permitted by the app; no secrets, tokens, or special repository access are required. The only precondition is `Shipit.github_teams` being non-empty (multi-team deployments), which is the documented/common configuration for restricting access. This is fully repeatable against arbitrary repositories/branches known to the attacker, and requires no live GitHub interaction to reproduce in tests.

### Recommendation
Enforce `current_user.authorized?` (or at least verify the user has access to the resolved repository/stack) inside `MergeStatusController#show`/`#check`/`#enqueue`/`#dequeue`, rather than fully skipping `force_github_authentication`. If the intent is to allow any authenticated Shipit user to use the browser-extension merge-status widget regardless of team, this should be an explicit, documented design decision rather than an implicit gap — but as currently written it diverges from the authorization model enforced everywhere else in the engine (`StacksController`, `RepositoriesController`, etc.).

### Proof of Concept
```ruby
test "GET show is exposed to logged-in but unauthorized (non-team) users" do
  session[:user_id] = shipit_users(:bob).id
  Shipit.stubs(:github_teams).returns([shipit_teams(:cyclimse_cooks)])
  refute_predicate shipit_users(:bob), :authorized?

  get :show, params: { referrer: 'https://github.com/Shopify/shipit-engine/pull/42', branch: 'master' }

  assert_response :ok
  assert_includes response.body, 'Ready to ship!' # stack_status data leaked despite authorized? == false
end
```
This contrasts with `StacksControllerTest#"current_user must be a member of at least a Shipit.github_teams"`, which asserts `:forbidden` for the same non-team user against `StacksController#index` [8](#0-7) , demonstrating the divergence is specific to `MergeStatusController`.

### Citations

**File:** app/controllers/shipit/merge_status_controller.rb (L4-6)
```ruby
  class MergeStatusController < ShipitController
    skip_authentication only: %i[check show]

```

**File:** app/controllers/shipit/merge_status_controller.rb (L10-19)
```ruby
    def show
      response.headers['X-Frame-Options'] = 'ALLOWALL'
      response.headers['Vary'] = 'X-Requested-With'

      if stack
        return render('logged_out') unless current_user.logged_in?

        if stale?(last_modified: [stack.updated_at, merge_request.updated_at].max, template: false)
          render(stack_status, layout: !request.xhr?)
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

**File:** app/controllers/concerns/shipit/authentication.rb (L8-16)
```ruby
      before_action :force_github_authentication
      helper_method :current_user
    end

    module ClassMethods
      def skip_authentication(*args)
        skip_before_action(:force_github_authentication, *args)
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

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```

**File:** app/views/shipit/merge_status/success.html.erb (L1-17)
```erb
<div class="branch-action-item js-details-container" <% if queue_enabled? %>data-queue-enabled<% end %> data-merge-status="<%= stack_status %>">
  <%= render 'merge_queue_button' if queue_enabled? %>
  <div class="branch-action-item-icon completeness-indicator">
    <%= render 'anchor', color: '#2cbe4e' %>
  </div>

  <h4 class="status-heading">
    <% if merge_request.waiting? %>
      <% if merge_request.all_status_checks_passed? %>
        Will be merged shortly!
      <% else %>
        Will be merged when required checks are passing.
      <% end %>
    <% else %>
      Ready to ship!
    <% end %>
  </h4>
```

**File:** test/controllers/stacks_controller_test.rb (L51-60)
```ruby
    test "current_user must be a member of at least a Shipit.github_teams" do
      session[:user_id] = shipit_users(:bob).id
      Shipit.stubs(:github_teams).returns([shipit_teams(:cyclimse_cooks), shipit_teams(:shopify_developers)])
      get :index
      assert_response :forbidden
      assert_equal(
        'You must be a member of cyclimse/cooks or shopify/developers to access this application.',
        response.body
      )
    end
```

**File:** app/views/shipit/merge_status/locked.html.erb (L1-19)
```erb
<div class="branch-action-item js-details-container" <% if queue_enabled? %>data-queue-enabled<% end %> data-merge-status="<%= stack_status %>">
  <%= render 'merge_queue_button' if queue_enabled? %>
  <div class="branch-action-item-icon completeness-indicator">
    <%= render 'anchor', color: '#bd2c00' %>
  </div>
  <h4 class="status-heading text-red">
    <% if merge_request.waiting? %>
      Will be merged shortly after the lock is removed!
    <% else %>
      Please hold off merging!
      <% if queue_enabled? %>
        Add it to the merge queue instead.
      <% end %>
    <% end %>
  </h4>
  <span class="status-meta">
    <%= link_to @stack.to_param, stack_url(@stack), target: '_blank', rel: 'noopener' %>
    is <strong>locked</strong> because: <strong><%= auto_link(emojify(@stack.lock_reason), html: { target: '_blank' }) %></strong>
  </span>
```
