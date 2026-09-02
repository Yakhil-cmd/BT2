### Title
Unauthenticated read of stack merge/build status via `MergeStatusController#check` - (File: app/controllers/shipit/merge_status_controller.rb)

### Summary
`MergeStatusController` exempts both `show` and `check` from the engine's mandatory `force_github_authentication` gate, but only `show` re-implements the login check inside the action body. `check` inherits the exemption without re-adding any authorization/authentication check, so it exposes stack merge-queue/build status to unauthenticated callers.

### Finding Description
The controller disables the global auth `before_action` for two actions: [1](#0-0) 

`show` compensates for the skip by manually gating on the session-bound user: [2](#0-1) 

`check`, part of the same `skip_authentication` group, contains no equivalent guard and directly computes and returns `stack_status`: [3](#0-2) 

`stack_status` resolves the target `Stack` either from an authenticated route parameter or, when absent, from an attacker-controlled `Referer`-style `params[:referrer]` string parsed by `ReferrerParser`, then queries `stack.merge_status`: [4](#0-3) [5](#0-4) 

This is the same class of bug as the reported issue: the engine's global authentication/authorization control ("Complication"/rule enforcement) is applied inconsistently across sibling code paths that share the same exemption list — one path (`show`) re-verifies the binding between "authentication skip" and "must still be logged in to see private data," while the sibling path (`check`) omits it entirely, breaking the equality `authentication required for skip_authentication actions == authentication enforced in the action body`.

### Impact Explanation
An unauthenticated network client can call `check` for any known/guessable `stack_id` (or via a spoofed `referrer` parameter resolving to any tracked repository/branch) and receive the stack's merge-queue/CI status (`success`, `pending`, `failure`, etc.) without any GitHub identity, Shipit session, or team membership. This matches the defined High-severity bucket of "unauthenticated read of stack state," since Shipit's entire access model is gated on `force_github_authentication` + `Shipit.github_teams` membership, both of which are bypassed here.

### Likelihood Explanation
High. No credentials, tokens, or prior access are required — only knowledge or brute-forcing of a `stack_id` (which follows a predictable `owner/name/environment` format) or a plausible GitHub PR URL to satisfy `ReferrerParser`'s regex. The route is reachable pre-authentication by design (`skip_authentication`), so the only missing control is the one line of authorization logic present in the sibling `show` action but absent from `check`.

### Recommendation
Add the same authentication/authorization guard used in `show` to `check` (or factor it into a shared `before_action`), e.g. return a 401/403 (or a neutral response) unless `current_user.logged_in? && current_user.authorized?`, mirroring `Shipit::Authentication#force_github_authentication`'s semantics instead of relying on action-specific reimplementation.

### Proof of Concept
1. Identify or guess a valid Shipit `stack_id` (e.g., `myorg/myrepo/production`) for a target instance where `Shipit.authentication_disabled?` is false and GitHub team-based authorization is enforced for all other pages.
2. Without any session cookie or authentication, issue:
   `GET /merge_status/myorg/myrepo/production/check` (format html or json)
3. Observe that the response returns `ok` / the merge/build status string (or JSON `{ "stack_status": "..." }`) directly, with no redirect to GitHub login and no "You must be a member of ..." rejection — unlike `GET /merge_status/myorg/myrepo/production` (`show`), which correctly renders the `logged_out` template for the same unauthenticated request.

### Citations

**File:** app/controllers/shipit/merge_status_controller.rb (L4-5)
```ruby
  class MergeStatusController < ShipitController
    skip_authentication only: %i[check show]
```

**File:** app/controllers/shipit/merge_status_controller.rb (L10-25)
```ruby
    def show
      response.headers['X-Frame-Options'] = 'ALLOWALL'
      response.headers['Vary'] = 'X-Requested-With'

      if stack
        return render('logged_out') unless current_user.logged_in?

        if stale?(last_modified: [stack.updated_at, merge_request.updated_at].max, template: false)
          render(stack_status, layout: !request.xhr?)
        end
      else
        render(html: '')
      end
    rescue ArgumentError
      render(html: '')
    end
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

**File:** app/controllers/shipit/merge_status_controller.rb (L58-81)
```ruby
    def stack_status
      @stack_status ||= stack.merge_status(backlog_leniency_factor: 1.0)
    end

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
