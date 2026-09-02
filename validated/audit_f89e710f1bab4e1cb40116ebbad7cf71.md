### Title
Unauthorized `authorized?` bypass: any logged-in-but-unauthorized GitHub user can read merge/stack status for arbitrary repositories via `MergeStatusController#show` - ([File: app/controllers/shipit/merge_status_controller.rb])

### Summary
`MergeStatusController` explicitly skips the `force_github_authentication` before_action — the only place `User#authorized?` (team membership) is enforced — for the `check` and `show` actions. `#show`'s sole guard is `current_user.logged_in?`, which is `true` for any `Shipit::User` record regardless of team membership, so any attacker who completes a single GitHub OAuth login can read full merge/stack status for any repository.

### Finding Description
The claimed binding is: for every response carrying stack data, `force_github_authentication` runs AND `current_user.authorized?` is true. This is false for `#show`.

- `MergeStatusController` declares `skip_authentication only: %i[check show]` [1](#0-0) , which calls `skip_before_action(:force_github_authentication, ...)` [2](#0-1) . This removes the only code path that checks `current_user.authorized?` [3](#0-2) .
- `#show`'s only guard is `return render('logged_out') unless current_user.logged_in?` [4](#0-3) .
- `Shipit::User#logged_in?` unconditionally returns `true` for any persisted `User` row [5](#0-4) , while `authorized?` is a separate, distinct check against `Shipit.github_teams` membership [6](#0-5) . Only `AnonymousUser` (unauthenticated session) has `logged_in? == false` [7](#0-6) .
- Any GitHub account that completes OAuth once gets a persisted `User` row (via `find_or_create_from_github`), giving `session[:user_id]` and `logged_in? == true`, independent of team membership.
- The `stack` lookup in `#show` resolves an arbitrary repository/branch either via `params[:stack_id]` (`Stack.from_param!`) or via the `referrer` query parameter parsed by `ReferrerParser`, which accepts any `https://github.com/<owner>/<repo>/pull/<n>` URL and queries `Stack` by `repositories: {owner:, name:}` with no ownership/authorization check tying the requester to that repository [8](#0-7) [9](#0-8) .
- Because `authorized?` is never evaluated on this path, the "You must be a member of ... to access this application" forbidden render in `force_github_authentication` (line 29 of `authentication.rb`) is unreachable for `#show`, and the full `stack_status`/`merge_request` payload is rendered instead [10](#0-9) .

Exploit flow: attacker completes a single legitimate GitHub OAuth login (creating a `Shipit::User` with `authorized? == false`), then issues `GET /merge_status?referrer=https://github.com/<any-owner>/<any-repo>/pull/1` (or `?stack_id=<n>`) with their session cookie. The response renders `stack_status` for that stack/repository — data the attacker was never authorized to view.

### Impact Explanation
This is an unauthenticated-adjacent (unauthorized) read of stack/merge status state: any account that can complete OAuth (which itself requires no privilege — it's just "log in with GitHub", not team membership) can enumerate and read merge queue/backlog state for any repository/stack configured in the Shipit instance, not just repositories it controls. This is repeatable per-request and applies uniformly across all tenants/stacks hosted by the instance, matching the "High - escalation into `Shipit.github_teams` authorization, unauthenticated read of stack state" impact category (read access equivalent to authorized-team members without being on any team).

### Likelihood Explanation
Preconditions are minimal: the attacker needs any GitHub account and must complete the standard OAuth login flow once (no membership in `Shipit.github_teams` required, no secrets needed). After that, exploitation is a single unauthenticated-looking GET request with attacker-controlled `referrer` or `stack_id` params. No rate limiting or additional checks stand in the way; the flaw is deterministic and repeatable against any stack in the instance.

### Recommendation
Do not skip `force_github_authentication` for `show`/`check` in `MergeStatusController`, or explicitly add an `authorized?` check inside `#show` (and `#check`) before rendering `stack_status`, mirroring the guard in `force_github_authentication`. If unauthenticated/public access to merge status is an intentional product decision, that should be an explicit, reviewed policy decision (e.g., a dedicated public-read scope) rather than an accidental byproduct of `skip_authentication`.

### Proof of Concept
```ruby
# test/controllers/shipit/merge_status_controller_test.rb (conceptual addition)
test '#show renders full stack data for logged-in but unauthorized user' do
  stack = shipit_stacks(:shipit)
  user = shipit_users(:walrus) # any persisted Shipit::User fixture
  user.stubs(:logged_in?).returns(true)
  user.stubs(:authorized?).returns(false)
  session[:user_id] = user.id

  get :show, params: {
    referrer: "https://github.com/#{stack.repository.owner}/#{stack.repository.name}/pull/1"
  }

  # Binding under test:
  # BEFORE: force_github_authentication runs -> current_user.authorized? == false -> forbidden rendered
  # AFTER (actual code): force_github_authentication is skipped for :show -> only logged_in? checked
  refute_includes response.body, 'You must be a member of'
  assert_response :success
  assert_includes response.body, stack.merge_status(backlog_leniency_factor: 1.0).to_s
end
```
This demonstrates that `authorized? == false` does not prevent full `stack_status` disclosure through `#show`, confirming the broken binding.

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

**File:** app/controllers/shipit/merge_status_controller.rb (L114-128)
```ruby
    class ReferrerParser
      URL_PATTERN = %r{\Ahttps://github\.com/([^/]+)/([^/]+)/pull/(\d+)}

      attr_reader :repo_owner, :repo_name, :pull_request_number

      def initialize(referrer)
        unless (match_info = URL_PATTERN.match(referrer.to_s))
          raise ArgumentError, "Invalid referrer: #{referrer.inspect}"
        end

        @repo_owner = match_info[1].downcase
        @repo_name = match_info[2].downcase
        @pull_request_number = match_info[3].to_i
      end
    end
```

**File:** app/controllers/concerns/shipit/authentication.rb (L12-16)
```ruby
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

**File:** app/models/shipit/anonymous_user.rb (L29-39)
```ruby
    def logged_in?
      false
    end

    def requires_fresh_login?
      false
    end

    def authorized?
      Shipit.authentication_disabled?
    end
```
