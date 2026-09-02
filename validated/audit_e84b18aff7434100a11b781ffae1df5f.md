### Title
Unauthenticated disclosure of private repository merge/task queue status via `MergeStatusController#check` - (File: app/controllers/shipit/merge_status_controller.rb)

### Summary
`MergeStatusController` explicitly skips `force_github_authentication` for the `check` (and `show`) actions [1](#0-0) . Unlike `show`, which gates the actual status payload behind `current_user.logged_in?` [2](#0-1) , `check` renders `stack.merge_status` unconditionally to any anonymous caller who can supply a `referrer` GitHub PR URL that resolves to a `Stack` [3](#0-2) .

### Finding Description
Binding claimed: `force_github_authentication` (before_action) == the gate that must be satisfied before a client can read `stack.merge_status` for any stack backed by a repository, private or public.

Actual code: `skip_authentication only: %i[check show]` removes `force_github_authentication` from both `check` and `show` [4](#0-3) . `show` re-adds an authorization check inline (`return render('logged_out') unless current_user.logged_in?`) before it exposes `stack_status` [2](#0-1) , but `check` has no equivalent check at all — it directly computes and renders `stack_status` (which memoizes `stack.merge_status(backlog_leniency_factor: 1.0)`) for both the HTML and JSON formats [3](#0-2) .

`stack` is resolved either by `params[:stack_id]` via `Stack.from_param!`, or — when absent — by parsing `params[:referrer]` with `ReferrerParser` for a `https://github.com/<owner>/<repo>/pull/<n>` URL and querying `Stack` by `repositories.owner`/`repositories.name` [5](#0-4) . Neither path checks the `Repository`'s visibility/private flag or any session/authorization state before returning `merge_status`. So for private repositories, the two sides of the binding diverge: the intended guard (`force_github_authentication`, or at minimum a `current_user.logged_in?`/`require_permission!` check like in `show`) is absent on `check`, while the actual code path unconditionally serves `stack.merge_status`.

The attacker's exact request: `GET /merge_status/check?referrer=https://github.com/<owner>/<private-repo>/pull/<n>` with no session cookie, or `GET /merge_status/check?stack_id=<id>` if the stack id/param is known or guessable. The response is `render(json: { stack_status: })` or plain text `ok`/status code 503, both of which reveal the aggregate merge/CI status of the private stack.

### Impact Explanation
This discloses the merge-queue/build status (e.g., pending, awaiting merge, checks failing) of a stack belonging to a repository the attacker has no access to, without authentication, matching the "High - unauthenticated read of stack state" category. It is repeatable against any stack whose owner/name/branch can be guessed or observed (e.g., via forks, cached URLs, or brute-forcing branch/environment names), and does not require any secret. It does not by itself leak commit SHAs, task logs, or deploy output — `stack.merge_status` returns an aggregate status string, not raw commit/task records — which somewhat bounds the blast radius compared to full task-stream disclosure.

### Likelihood Explanation
The only precondition is knowledge (or a guess) of the private repository's `owner`/`name` and either a PR number (to satisfy `ReferrerParser`) or the `stack_id`/branch. No Shipit session, API token, or GitHub credential is required, and the route is reachable to any internet client per the engine's routes. Cost to the attacker is a single unauthenticated GET request, fully repeatable and scriptable across arbitrary target repos/stacks.

### Recommendation
Add the same authorization guard used in `show` (`current_user.logged_in?` and/or `require_permission!`) to `check` before computing/rendering `stack_status`, or restrict `check`'s unauthenticated behavior to repositories explicitly marked public, so that private repositories' merge/task state cannot be read without authentication.

### Proof of Concept
Minitest (`test/controllers/merge_status_controller_test.rb`) — add a case: create a `Stack` backed by a `Repository` with private visibility and a pending/failed merge status; issue `get :check, params: { referrer: "https://github.com/#{owner}/#{repo}/pull/1" }` with no session set (`session[:user_id]` absent); assert `response.body` / parsed JSON does NOT contain `stack_status` (or that the response is `403`/redirect), matching the binding `force_github_authentication` must gate `stack.merge_status` for private-repo stacks; currently the same request returns `200` with `{"stack_status":"pending"}` (or similar), proving the divergence.

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

**File:** app/controllers/shipit/merge_status_controller.rb (L39-60)
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

    private

    def cache_seed
      "#{request.xhr? ? 'partial' : 'full'}-#{Shipit.revision}"
    end

    def stack_status
      @stack_status ||= stack.merge_status(backlog_leniency_factor: 1.0)
    end
```

**File:** app/controllers/shipit/merge_status_controller.rb (L62-85)
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
```
