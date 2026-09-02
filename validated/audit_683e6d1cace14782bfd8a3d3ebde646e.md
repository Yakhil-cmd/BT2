### Title
`MergeStatusController#show` sets `X-Frame-Options: ALLOWALL`, enabling clickjacking of merge-queue enqueue/dequeue actions - (File: `app/controllers/shipit/merge_status_controller.rb`)

### Summary
`MergeStatusController#show` unconditionally overrides frame protection with `response.headers['X-Frame-Options'] = 'ALLOWALL'` and sets no `Content-Security-Policy: frame-ancestors` anywhere else in the controller, application controller, or engine config. This allows an attacker to embed the authenticated user's `/merge_status?referrer=...` page in a hidden/disguised cross-origin `<iframe>` and use standard clickjacking to make the victim's genuine, authenticated request hit the real `enqueue`/`dequeue` UI, causing an unintended `PUT`/`DELETE /merge_status/*stack_id/pull/:number` merge-queue action.

### Finding Description
Binding claimed broken: `victim's perceived click target == the click target that actually receives the click`. Normally Rails' default `X-Frame-Options: SAMEORIGIN` (or an explicit `frame-ancestors`) prevents this page from being rendered inside a cross-origin frame at all, which is the entire mitigation for clickjacking. Here, `MergeStatusController#show` (`app/controllers/shipit/merge_status_controller.rb:11`) explicitly sets `ALLOWALL`, and no other layer (`ApplicationController`, `ShipitController` at `app/controllers/shipit/shipit_controller.rb`, or engine-level middleware) sets a competing `X-Frame-Options` or CSP `frame-ancestors` for this action — confirmed by grep across the repo returning only this one match.

`show` is reachable without authentication guard bypass (`skip_authentication only: %i[check show]` at line 5), but it renders `logged_out` unless `current_user.logged_in?`, so the page content (including the enqueue/dequeue buttons) is only meaningfully rendered when the browser has a valid Shipit session — i.e., exactly the victim scenario. The attacker supplies an arbitrary `referrer=https://github.com/{owner}/{repo}/pull/{number}` query param, which `ReferrerParser` (lines 114-127) parses to pick an arbitrary stack/PR the attacker chooses, and frames that URL invisibly/disguised over decoy content. When the victim clicks what they believe is an unrelated element, the click actually lands on the framed `enqueue_merge_request_path`/`dequeue_merge_request_path` button, triggering the real `PUT`/`DELETE /merge_status/*stack_id/pull/:number` (routes at `config/routes.rb:55-56`) with the victim's valid session cookie and CSRF token (since the page itself, and its embedded token, are genuine — `protect_from_forgery with: :exception` in `app/controllers/shipit/shipit_controller.rb:25` does not defend against clickjacking, only against forged cross-origin form submission).

`enqueue`/`dequeue` (lines 27-37) then call `MergeRequest.request_merge!(stack, params[:number], current_user)` or `merge_request.cancel!` respectively as the victim's `current_user`, performing a state change the victim did not intend, on a stack the attacker chose.

### Impact Explanation
An attacker can force any authenticated Shipit user who visits an attacker-controlled page to enqueue or dequeue a pull request in a stack's merge queue without their consent, using the victim's own valid session/authorization. This is a real unauthorized state change (merge-queue enqueue/dequeue) triggered on behalf of a legitimate, authorized user, repeatable per victim/per click and against any stack/PR the attacker names via `referrer`. It does not by itself perform a full merge/deploy/rollback (that still requires the normal deploy pipeline and CI checks), so the direct write is limited to queue state (`waiting`/cancelled merge_request records), matching the "High" severity band cited in the question (unauthorized state-changing merge-queue action by a tricked authenticated victim) rather than the "Critical: unauthorized deploy/rollback/merge" band.

### Likelihood Explanation
Preconditions: victim must have an active Shipit session and be a member of an authorized `Shipit.github_teams` group (per `force_github_authentication`/`User#authorized?`), and must be lured to click on attacker-controlled content while the framed page silently loads underneath/behind it. No Shipit or GitHub secrets are required by the attacker; only a crafted HTML page and a plausible `referrer` PR URL for the targeted stack. This is a standard, low-cost clickjacking setup (invisible iframe + overlay), fully feasible and repeatable against any number of victims/stacks since `referrer` and `stack_id` are attacker-controlled request parameters.

### Recommendation
Remove the `response.headers['X-Frame-Options'] = 'ALLOWALL'` override in `MergeStatusController#show`, or replace it with a scoped `frame-ancestors` CSP that only permits the specific, trusted embedding contexts (e.g., the GitHub PR page origin `https://github.com`) if browser-extension/PR-embedding is a required feature. If framing must be allowed for a legitimate browser extension use case, additionally require a fresh, action-specific confirmation (e.g., re-auth or a non-forgeable double-submit gesture) before executing `enqueue`/`dequeue`, so that framing alone cannot trigger the state change.

### Proof of Concept
Minitest plan (`test/controllers/shipit/merge_status_controller_test.rb`, no live GitHub required):
```ruby
test '#show sets X-Frame-Options to ALLOWALL, disabling clickjacking protection' do
  stack = shipit_stacks(:shipit)
  session[:user_id] = shipit_users(:walrus).id
  get merge_status_url(stack_id: stack.to_param, referrer: "https://github.com/#{stack.repository.owner}/#{stack.repository.name}/pull/1")
  assert_response :success
  # Binding check: expect protective header (SAMEORIGIN or absent-but-CSP-frame-ancestors),
  # but observe attacker-favorable value instead.
  assert_equal 'ALLOWALL', response.headers['X-Frame-Options']
  assert_nil response.headers['Content-Security-Policy'] # no frame-ancestors fallback anywhere
end

test 'enqueue/dequeue execute as current_user with only session + valid CSRF, no framing check' do
  stack = shipit_stacks(:shipit)
  merge_request = shipit_merge_requests(:pending) # arbitrary fixture PR
  session[:user_id] = shipit_users(:walrus).id
  put enqueue_merge_request_path(stack_id: stack.to_param, number: merge_request.number)
  assert_response :success
  assert merge_request.reload.waiting?
  # No server-side signal distinguishes a genuine top-level click from a framed/clickjacked one.
end
```
These assert both sides of the binding: (1) the header value actually served is `ALLOWALL` with no compensating CSP, confirming frame protection is disabled for this page; and (2) the state-changing `enqueue`/`dequeue` endpoints execute purely on session + CSRF token with no anti-framing/anti-clickjacking signal, confirming the divergence between "victim's intended click" and "action executed" is possible once framing is permitted. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

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

**File:** app/controllers/shipit/shipit_controller.rb (L23-26)
```ruby
    # Prevent CSRF attacks by raising an exception.
    # For APIs, you may want to use :null_session instead.
    protect_from_forgery with: :exception

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

**File:** config/routes.rb (L54-56)
```ruby
  get '/merge_status', action: :show, controller: :merge_status, as: :merge_status
  put '/merge_status/*stack_id/pull/:number', action: :enqueue, controller: :merge_status, id: stack_id_format, as: :enqueue_merge_request
  delete '/merge_status/*stack_id/pull/:number', action: :dequeue, controller: :merge_status, id: stack_id_format, as: :dequeue_merge_request
```
