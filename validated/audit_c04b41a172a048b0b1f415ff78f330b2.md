### Title
Unauthenticated disclosure of private stack CI/merge status via `MergeStatusController#check` - (File: `app/controllers/shipit/merge_status_controller.rb`)

### Summary
`MergeStatusController` skips Shipit's GitHub-team authentication for its `check` and `show` actions, on the assumption that this endpoint is only used for the innocuous "merge status" widget embedded in GitHub pull requests. `show` at least checks `current_user.logged_in?` before rendering real status, but `check` performs no such check at all, so `stack_status` (derived from CI/merge-queue state of a resolved `Stack`) is returned to a fully unauthenticated caller.

### Finding Description
The controller declares: [1](#0-0) 

The `check` action never verifies `current_user.logged_in?` (unlike `show`), and simply renders the computed `stack_status`: [2](#0-1) 

The `stack` used to compute that status is resolved entirely from request parameters, not from any authenticated GitHub identity: either directly via `params[:stack_id]`, or — when absent — from a `referrer` query parameter that is parsed client-side-controlled with a simple regex (`ReferrerParser`) matching a GitHub PR URL shape, with no verification that the requester actually has access to, or was referred by, that GitHub PR/repository: [3](#0-2) [4](#0-3) 

This breaks the intended binding "GitHub identity authenticated == entity whose state is disclosed": normal Shipit access is gated by `Shipit::Authentication#force_github_authentication`, which requires the user to be logged in via GitHub OAuth and be a member of `Shipit.github_teams`: [5](#0-4) 

but `merge_status#check` is explicitly exempted from this gate (`skip_authentication only: %i[check show]`) and, unlike `show`, does not compensate with its own `current_user.logged_in?` check, so any unauthenticated caller can query it by supplying `stack_id` or a forged `referrer`/`branch` for any repo/branch known to the Shipit instance.

### Impact Explanation
An unauthenticated attacker can enumerate/query the CI, merge-queue, and deploy-readiness status (`success`/`pending`/`failure`/`locked`/`backlogged`, etc.) of any stack, including stacks backing private repositories, without any GitHub team membership or session. This matches the "High - unauthenticated read of stack state" impact category: it discloses internal deployment/CI state that should only be visible to authorized, GitHub-team-authenticated users.

### Likelihood Explanation
High likelihood: the endpoint is intentionally public-facing (it is embedded as an iframe in GitHub PRs, hence `X-Frame-Options: ALLOWALL` and `skip_authentication`), reachable without any credentials, tokens, or repository write access — only knowledge or guessing of a `stack_id` or a repo owner/name/branch triple, which are generally guessable/public information (GitHub org/repo names are usually public even if repo content is private).

### Recommendation
Require `current_user.logged_in?` (and, ideally, `current_user.authorized?`) in the `check` action exactly as is already done in `show`, or remove the unauthenticated exemption unless the disclosed information (pass/fail-only, no repo/branch names) is deliberately intended to be public. At minimum, gate `check` behind the same login check used by `show` before computing/rendering `stack_status`.

### Proof of Concept
1. As an anonymous (logged-out) client, issue: `GET /merge_status/check.json?referrer=https://github.com/PrivateOrg/private-repo/pull/1&branch=main`.
2. `MergeStatusController#check` resolves `stack` via `ReferrerParser` from the `referrer` param without checking `current_user.logged_in?`.
3. The response returns `{"stack_status": "success"}` (or `pending`/`failure`/etc.), or plain `ok`/503, disclosing the CI/deploy state of the private stack to the unauthenticated caller.

Note: I was unable to fully confirm from the available index whether any upstream middleware (outside `app/**`/`lib/shipit/**`/`config/routes.rb`) additionally restricts unauthenticated access to this route in a default deployment; the analysis is based solely on the controller code and `Shipit::Authentication` concern as found in the engine.

### Citations

**File:** app/controllers/shipit/merge_status_controller.rb (L4-5)
```ruby
  class MergeStatusController < ShipitController
    skip_authentication only: %i[check show]
```

**File:** app/controllers/shipit/merge_status_controller.rb (L39-50)
```ruby
    def check
      respond_to do |format|
        format.html do
          if stack_status == 'success'
            render(plain: 'ok')
          else
            render(plain: stack_status, status: 503)
          end
        end
        format.json { render(json: { stack_status: }) }
      end
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

**File:** app/controllers/shipit/merge_status_controller.rb (L114-127)
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
