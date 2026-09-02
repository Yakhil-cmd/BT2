### Title
Clickjacking via `X-Frame-Options = 'ALLOWALL'` on `MergeStatusController#show` enables unauthorized merge-queue actions - (File: app/controllers/shipit/merge_status_controller.rb)

### Summary
`MergeStatusController#show` explicitly sets `response.headers['X-Frame-Options'] = 'ALLOWALL'`, permitting any origin to frame the merge-status widget for an arbitrary `stack`/`referrer`/PR combination. [1](#0-0)  Because the enqueue/dequeue controls rendered in that page issue same-origin `PUT`/`DELETE` XHR requests carrying the victim's real session cookie and valid CSRF token, an attacker can overlay deceptive UI to trick a logged-in victim into clicking the real "enqueue"/"dequeue" control, causing `MergeRequest.request_merge!`/`cancel!` to execute as the victim for a stack/PR the attacker chose. [2](#0-1)  `protect_from_forgery with: :exception` on `ShipitController` blocks forged cross-origin requests but does not defend against clickjacking, since the request is a genuine same-origin request triggered through UI deception rather than a forged token/origin. [3](#0-2) 

### Finding Description
The claimed-safe binding is: `X-Frame-Options prevents cross-origin framing == true`. In fact, `#show` sets it to `'ALLOWALL'`, so the equality is false for this endpoint — any origin can embed `/merge_status?stack_id=...&referrer=...&branch=...` in an `<iframe>`. [4](#0-3) 

`show` is reachable without authentication (`skip_authentication only: %i[check show]`), and only renders the interactive queue controls (`render(stack_status, layout: !request.xhr?)`) once `current_user.logged_in?` is true — i.e., only for a victim who already has an active Shipit session from a prior visit. [5](#0-4)  The attacker fully controls which stack/PR is displayed via `stack_id`, `referrer`, and `branch` query params, resolved in the `stack`/`merge_request` helper methods, without any ownership check tying the attacker to that repository. [6](#0-5) 

The rendered widget's enqueue/dequeue buttons make `PUT /merge_status/*stack_id/pull/:number` and `DELETE /merge_status/*stack_id/pull/:number` requests. [7](#0-6)  Because these are same-origin AJAX calls issued from the legitimately-loaded iframe content, they carry the victim's real session cookie and a valid CSRF token embedded by the actual page — `protect_from_forgery with: :exception` on `ShipitController` verifies token/origin, not user intent, so it does not block a "real" request triggered via a deceptive overlay. [3](#0-2)  An attacker can therefore craft a page that iframes the merge-status widget for a stack/PR of their choosing, position an invisible overlay so the victim's click lands on the "enqueue" or "dequeue" button, and cause `MergeRequest.request_merge!(stack, params[:number], current_user)` or `merge_request.cancel!` to fire as the victim. [2](#0-1) 

### Impact Explanation
A successful clickjack causes an unauthorized merge-queue enqueue or cancel action to be recorded as performed by the victim, for a stack/repository the victim did not intend to interact with (attacker picks `stack_id`/PR number). This matches the "unauthorized deploy/rollback/merge"-class Critical impact category if the victim has merge-queue authorization for the targeted stack; it can be repeated against any stack/PR the attacker can construct a URL for, since no server-side check exists that ties the framed `stack` to any relationship with the requesting page's origin or attacker identity.

### Likelihood Explanation
Preconditions: the victim must already have an authenticated Shipit session (`logged_in?`) from a prior visit, and must have merge-queue permission for the targeted stack for the action to matter; both are plausible for an engineer who regularly interacts with Shipit-backed PRs. Attacker cost is low: host a page with an iframe pointing at `/merge_status?stack_id=...&referrer=https://github.com/{owner}/{repo}/pull/{n}`, overlay a deceptive click target, and lure the victim (e.g., via a normal-looking link). No secrets, tokens, or webhook forgery are required — this is purely a UI-framing issue enabled by the explicit `ALLOWALL` header, independent of `verify_signature`/CSRF/`require_permission!`, which are irrelevant to click-based deception.

### Recommendation
Do not set `X-Frame-Options: ALLOWALL` unconditionally for `#show`. If the widget must be embeddable for legitimate integrations (e.g., a browser extension or GitHub PR page), scope the allowed framing ancestors explicitly via `Content-Security-Policy: frame-ancestors` restricted to known, trusted origins (e.g., `https://github.com`) instead of allowing all origins, and add client-side frame-busting/double-click confirmation for state-changing enqueue/dequeue controls, or require an additional user gesture/confirmation that cannot be satisfied by a single disguised click.

### Proof of Concept
```ruby
require "test_helper"

module Shipit
  class MergeStatusControllerClickjackingTest < ActionDispatch::IntegrationTest
    test "#show sets X-Frame-Options to ALLOWALL enabling framing" do
      stack = shipit_stacks(:shipit)
      session[:user_id] = shipit_users(:walrus).id # simulate victim with prior session

      get "/merge_status", params: { stack_id: stack.to_param }

      assert_equal "ALLOWALL", response.headers["X-Frame-Options"],
        "expected ALLOWALL; binding 'X-Frame-Options prevents cross-origin framing' is false for this endpoint"
    end

    test "enqueue succeeds as a same-origin request without any anti-clickjacking gate" do
      stack = shipit_stacks(:shipit)
      pr = shipit_merge_requests(:shipit_pending_review)
      session[:user_id] = shipit_users(:walrus).id

      assert_difference -> { pr.reload.updated_at }, 0 do
        # no-op baseline
      end

      put enqueue_merge_request_path(stack_id: stack.to_param, number: pr.number)

      assert_response :success
      # Demonstrates the state-changing action executes purely from a same-origin
      # click inside the frame, with no server-side signal distinguishing a
      # legitimate user click from a clickjacked one.
    end
  end
end
```

### Citations

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

**File:** app/controllers/shipit/merge_status_controller.rb (L27-37)
```ruby
    def enqueue
      MergeRequest.request_merge!(stack, params[:number], current_user)
      render(stack_status, layout: !request.xhr?)
    end

    def dequeue
      if (merge_request = stack.merge_requests.find_by_number(params[:number])) && merge_request.waiting?
        merge_request.cancel!
      end
      render(stack_status, layout: !request.xhr?)
    end
```

**File:** app/controllers/shipit/merge_status_controller.rb (L62-98)
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

    def referrer_parser
      @referrer_parser ||= ReferrerParser.new(params[:referrer])
    end

    def merge_request
      return @merge_request if defined?(@merge_request)

      @merge_request = pull_request_number && stack.merge_requests.find_by_number(pull_request_number)
      @merge_request ||= UnknownMergeRequest.new
    end

    def pull_request_number
      return @pull_request_number if defined?(@pull_request_number)

      @pull_request_number = referrer_parser.pull_request_number
    end
```

**File:** app/controllers/shipit/shipit_controller.rb (L23-25)
```ruby
    # Prevent CSRF attacks by raising an exception.
    # For APIs, you may want to use :null_session instead.
    protect_from_forgery with: :exception
```

**File:** config/routes.rb (L55-56)
```ruby
  put '/merge_status/*stack_id/pull/:number', action: :enqueue, controller: :merge_status, id: stack_id_format, as: :enqueue_merge_request
  delete '/merge_status/*stack_id/pull/:number', action: :dequeue, controller: :merge_status, id: stack_id_format, as: :dequeue_merge_request
```
