### Title
Unconditional `X-Frame-Options: ALLOWALL` on `MergeStatusController#show` enables clickjacking of authenticated enqueue/dequeue actions - (File: app/controllers/shipit/merge_status_controller.rb)

### Summary
`MergeStatusController#show` unconditionally sets `response.headers['X-Frame-Options'] = 'ALLOWALL'`, overriding Rails' default `SAMEORIGIN` framing protection for every caller, with no allow-list of trusted origins. This lets an attacker embed the logged-in operator's merge-status widget (which renders `enqueue`/`dequeue` controls) inside an attacker-controlled page and, via `SameSiteCookieMiddleware` forcing `SameSite=None` on all cookies over TLS, the operator's session cookie is still sent when the framed page loads, enabling UI-redress-driven clicks against `/enqueue`/`/dequeue`.

### Finding Description
The claimed binding is: "the frame ancestor rendering this authenticated UI == an origin the operator trusts." In the code, this binding is broken unconditionally: [1](#0-0) 
`response.headers['X-Frame-Options'] = 'ALLOWALL'` is set for every request to `#show`, with no check of `Sec-Fetch-Site`, `Origin`, `Referer`, or any allow-list — any origin can embed it. This contrasts with `ShipitController`, which does not touch `X-Frame-Options` at all and therefore inherits Rails' `action_dispatch.default_headers` default of `SAMEORIGIN`.

`show` renders the full merge-status widget, including the enqueue/dequeue buttons, once `current_user.logged_in?` is true: [2](#0-1) 
`current_user` is derived purely from `session[:user_id]`: [3](#0-2) 
and `enqueue`/`dequeue` require authentication (only `check`/`show` are exempted): [4](#0-3) [5](#0-4) 

Because the widget and its buttons execute inside the Shipit origin's own iframe (the attacker only frames the real page, they don't proxy it), a click triggered by UI redress fires a same-origin request from the framed document, carrying whatever CSRF token was actually rendered for that operator's session. `protect_from_forgery with: :exception` therefore does not stop this, since the token is legitimate — it's the browser's *rendering* that's spoofed, not the request's origin. [6](#0-5) 

Additionally, `SameSiteCookieMiddleware` rewrites all HTTPS cookies to `SameSite=None`, which means the operator's session cookie is sent even when the top-level page is a third-party attacker origin and Shipit is only loaded in an iframe: [7](#0-6) 
This removes what would otherwise be a partial mitigation (`SameSite=Lax/Strict` blocking the session cookie on cross-site framed navigation).

Attack: attacker crafts `https://evil.example/click.html` containing `<iframe src="https://shipit.example/merge_status?stack_id=<real_stack>" style="opacity:0">` and overlays a decoy button aligned with the real enqueue/dequeue control. When a logged-in operator (who has a valid Shipit session) visits the attacker page and clicks the decoy, the click lands on the real enqueue/dequeue button inside the iframe, firing a legitimate same-origin authenticated request.

None of the listed guards apply here: `verify_signature`/webhook checks are irrelevant (this is a browser-session flow, not a webhook), `force_github_authentication` only gates whether the user is logged in (the victim already is), and there is no CSRF defense against UI redress by design (CSRF tokens protect against forged *origin*, not forged *visual context*).

### Impact Explanation
An attacker can force an authenticated operator to unknowingly click `enqueue` or `dequeue` for an arbitrary pull request against a real merge queue, causing `MergeRequest.request_merge!` or `merge_request.cancel!` to run with the victim's identity as the actor, on any stack the attacker chooses to embed (the attacker only needs to know/guess a `stack_id` or referrer URL — no secret required). This is repeatable per click and can be scripted to fire on page load/mouseover across many operators' sessions, though each exploitation instance requires one victim click while framed. The blast radius is confined to merge-queue state (queue position, enqueue/cancel) for the targeted stack; it does not directly grant `Shipit.github_teams` membership, leak secrets, or achieve RCE.

### Likelihood Explanation
Preconditions: the victim must have an active Shipit session (i.e., be a logged-in, authorized operator) and must visit/interact with the attacker's page while that session is valid; no Shipit or GitHub secret is required. Attacker cost is minimal — a static HTML page with an iframe and CSS overlay, and knowledge of the target `stack_id` (visible in normal Shipit URLs, not secret). This is standard UI-redress feasibility, and the finding is fully attacker-controlled and repeatable against any stack whose `stack_id` is known.

### Recommendation
Do not set `X-Frame-Options: ALLOWALL` unconditionally. Either remove the override (falling back to Rails' default `SAMEORIGIN`), or replace it with a `Content-Security-Policy: frame-ancestors` allow-list restricted to the specific, trusted GitHub PR-page origin (`https://github.com`) rather than `*`/`ALLOWALL`, and pair it with confirmation dialogs or a fresh CSRF/interaction check (e.g., double-submit or explicit user gesture validation) on the state-changing `enqueue`/`dequeue` endpoints so a single redressed click cannot mutate queue state.

### Proof of Concept
```ruby
# test/controllers/shipit/merge_status_controller_test.rb
require 'test_helper'

module Shipit
  class MergeStatusControllerFramingTest < ActionController::TestCase
    tests MergeStatusController

    test '#show sets X-Frame-Options to ALLOWALL regardless of caller, breaking framing protection' do
      get :show, params: { referrer: 'https://github.com/shipit/shipit/pull/1' }
      # Binding under test: frame_ancestor_allowed == trusted_origin
      # Actual: frame_ancestor_allowed == '*' (ALLOWALL) for every request
      assert_equal 'ALLOWALL', response.headers['X-Frame-Options']
    end

    test 'other Shipit controllers retain default SAMEORIGIN, contrasting with #show' do
      get :check, params: { referrer: 'https://github.com/shipit/shipit/pull/1' }
      # `check` and `show` share skip_authentication, but only #show forges ALLOWALL
      refute_equal 'ALLOWALL', response.headers['X-Frame-Options']
    end
  end
end
```
This demonstrates the divergence: `#show` always emits `ALLOWALL` (equality broken — any origin can be a frame ancestor), while comparable actions retain the Rails default, confirming the framing protection is deliberately disabled only for the page rendering the enqueue/dequeue controls.

### Citations

**File:** app/controllers/shipit/merge_status_controller.rb (L5-5)
```ruby
    skip_authentication only: %i[check show]
```

**File:** app/controllers/shipit/merge_status_controller.rb (L10-12)
```ruby
    def show
      response.headers['X-Frame-Options'] = 'ALLOWALL'
      response.headers['Vary'] = 'X-Requested-With'
```

**File:** app/controllers/shipit/merge_status_controller.rb (L14-19)
```ruby
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

**File:** app/controllers/concerns/shipit/authentication.rb (L36-42)
```ruby
    def current_user
      @current_user ||= find_current_user || AnonymousUser.new
    end

    def find_current_user
      session[:user_id].present? && User.find_by(id: session[:user_id])
    end
```

**File:** app/controllers/shipit/shipit_controller.rb (L23-25)
```ruby
    # Prevent CSRF attacks by raising an exception.
    # For APIs, you may want to use :null_session instead.
    protect_from_forgery with: :exception
```

**File:** lib/shipit/same_site_cookie_middleware.rb (L14-24)
```ruby
      if headers && headers['Set-Cookie'] &&
         Rack::Request.new(env).ssl?

        set_cookies = headers['Set-Cookie'].split(COOKIE_SEPARATOR).compact
        set_cookies.map! do |cookie|
          cookie << '; Secure' if cookie !~ /;\s*secure/i
          cookie << '; SameSite=None' unless cookie.match?(/;\s*samesite=/i)
          cookie
        end

        headers['Set-Cookie'] = set_cookies.join(COOKIE_SEPARATOR)
```
