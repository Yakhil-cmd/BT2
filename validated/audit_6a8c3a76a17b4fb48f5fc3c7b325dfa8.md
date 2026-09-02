### Title
`GET /merge_status` leaks stack existence to unauthenticated users via response body difference - (File: `app/controllers/shipit/merge_status_controller.rb`)

### Summary
`Shipit::MergeStatusController#show` is exempted from `force_github_authentication` via `skip_authentication only: %i[check show]`, and resolves a `Stack` purely from attacker-controlled `params[:referrer]` (parsed by `ReferrerParser` into `repo_owner`/`repo_name`) and `params[:branch]`. When a matching stack exists, an anonymous caller receives a non-blank `logged_out` template body (containing "please log in"); when no stack matches, the response body is empty. This gives any unauthenticated internet user a binary oracle to enumerate the existence of `{owner, repo, branch}` stacks on the target Shipit instance.

### Finding Description
The broken invariant: the controller assumes `disclosure(stack_existence) == authorized?(current_user)`, but in `show` the branch is:
```
if stack
  return render('logged_out') unless current_user.logged_in?
  ...
else
  render(html: '')
end
``` [1](#0-0) 

`stack` is derived entirely from unauthenticated request params:
```
scope = Stack.order(...).includes(:repository).where(
  repositories: { owner: referrer_parser.repo_owner, name: referrer_parser.repo_name }
)
scope = params[:branch] ? scope.where(branch: params[:branch]) : scope.where(environment: 'production')
scope.first
``` [2](#0-1) 

`ReferrerParser` accepts any `https://github.com/<owner>/<repo>/pull/<n>` string, fully attacker-controlled and requires no proof of ownership or GitHub authentication: [3](#0-2) 

`skip_authentication` bypasses `force_github_authentication` (the concern that normally enforces `current_user.logged_in?` and `current_user.authorized?`) specifically for `check` and `show`: [4](#0-3) [5](#0-4) 

Because `current_user` is an `AnonymousUser` (not logged in) when there is no session, the `unless current_user.logged_in?` check inside `show` always fires for a matching stack, returning the `logged_out` template — a distinguishable, non-blank 200 response — while a non-matching repo/branch returns an empty 200 body. This divergence is directly demonstrated by the engine's own test suite: [6](#0-5) 

Exploit flow: an attacker with no Shipit session sends `GET /merge_status?referrer=https://github.com/<owner>/<repo>/pull/1&branch=<branch>` for arbitrary `<owner>/<repo>/<branch>` combinations and observes whether the body is blank (no stack) or contains the login prompt (stack exists). No `verify_signature`, `authorized?`, or `require_permission!` guard applies to this branch since `show` is explicitly exempted from `force_github_authentication`.

### Impact Explanation
The attacker can determine, for any repository name/owner and branch they can guess or already know (including private repos not otherwise disclosed to them), whether a Shipit stack is configured to deploy that repo/branch. This is a metadata/existence disclosure, not disclosure of task output, credentials, or full stack state — the `show` action does not leak `stack_status`, task logs, or deploy details to an anonymous user (that data is only rendered once `current_user.logged_in?` is true, i.e., the actual `merge_status` partial with detailed content is gated). The blast radius is limited to a boolean "stack exists for owner/repo/branch" fact per request, repeatable against arbitrary repo/branch names, across all repositories managed by the instance. This falls short of the "High" bar defined in the question (unauthenticated read of stack state, task streams, or deploy output) since only existence — not state/content — leaks.

### Likelihood Explanation
Trivial to exploit: no Shipit session, GitHub credentials, or webhook secrets required; a single unauthenticated HTTP GET with attacker-chosen `referrer` and `branch` params suffices, and it is fully repeatable/automatable across many owner/repo/branch guesses.

### Recommendation
Return a uniform response (e.g., always render blank or always render `logged_out`) for anonymous users regardless of whether a matching stack exists, so that the branch in `show` does not depend on `stack.present?` before checking `current_user.logged_in?`. For example, check `current_user.logged_in?` first and short-circuit with a constant response before attempting stack lookup, or make the "no stack" and "not logged in" cases return byte-identical responses.

### Proof of Concept
```ruby
# test/controllers/merge_status_controller_test.rb
test "anonymous show discloses stack existence via body length" do
  session.delete(:user_id)

  get :show, params: { referrer: 'https://github.com/Shopify/shipit-engine/pull/42', branch: 'master' }
  existing_body = response.body
  assert_response :ok

  get :show, params: { referrer: 'https://github.com/Shopify/unknown-repo/pull/42', branch: 'master' }
  missing_body = response.body
  assert_response :ok

  # Binding under test: disclosure(stack_exists) should equal disclosure(!stack_exists)
  # i.e. existing_body == missing_body for an unauthenticated caller.
  refute_equal existing_body, missing_body, "anonymous response distinguishes stack existence"
end
```
This confirms the divergence already implied by the two pre-existing tests `"GET anonymous show returns a login message"` and `"GET anonymous show when there is no matching stack is blank"` [6](#0-5) , which together prove the binary oracle exists but establish no impact beyond existence disclosure.

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

**File:** app/controllers/concerns/shipit/authentication.rb (L12-34)
```ruby
    module ClassMethods
      def skip_authentication(*args)
        skip_before_action(:force_github_authentication, *args)
      end
    end

    private

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

**File:** test/controllers/merge_status_controller_test.rb (L25-37)
```ruby
    test "GET anonymous show returns a login message" do
      session.delete(:user_id)
      get :show, params: { referrer: 'https://github.com/Shopify/shipit-engine/pull/42', branch: 'master' }
      assert_response :ok
      assert_includes response.body.downcase, 'please log in'
    end

    test "GET anonymous show when there is no matching stack is blank" do
      session.delete(:user_id)
      get :show, params: { referrer: 'https://github.com/Shopify/unknown-repo/pull/42', branch: 'master' }
      assert_response :ok
      assert_predicate response.body, :blank?
    end
```
