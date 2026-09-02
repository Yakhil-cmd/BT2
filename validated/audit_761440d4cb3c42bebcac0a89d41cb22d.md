Confirmed: `status.target_url` is rendered directly as a raw `href` attribute in `app/views/shipit/statuses/_status.html.erb:1` and `app/views/shipit/statuses/_group.html.erb:12`, with no origin/repository validation applied before rendering.

### Title
Cross-repository Status forgery via unscoped SHA lookup in `StatusHandler#process` writes attacker-controlled `target_url`/`description`/`context` into an unrelated stack - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` resolves target commits solely by `Commit.where(sha: params.sha)` with no comparison to the webhook's `repository.full_name`, and `Status.replicate_from_github!` persists `state`/`description`/`target_url`/`context` from the webhook payload verbatim onto whatever `stack_id` the matched commit happens to belong to. Since git commit SHAs are public, deterministic, and content-addressed (not secrets), any party able to obtain one genuinely GitHub-signed `status` webhook for a commit SHA that also exists as a `Commit` row in a different, unrelated stack can inject arbitrary `target_url`/`description`/`context` into that other stack's UI.

### Finding Description
Claimed binding: `Status.stack_id` written by `replicate_from_github!` must equal the `stack_id` whose `Stack#repository.full_name` matches the webhook payload's `repository.full_name` (i.e., only a status-provider with write/admin access to repository B's GitHub App installation may write a `Status` visible under stack B).

Actual code path:
1. `WebhooksController#create` parses the raw JSON and dispatches to `Shipit::Webhooks.for_event(event)` handlers [1](#0-0) .
2. `verify_signature` selects the `GitHubApp` purely from `repository.owner.login` in the payload and checks the HMAC against that app's `webhook_secret` [2](#0-1) . Critically, `Shipit.github` in the common single-app (non-multi-org) configuration ignores the `organization:` argument for config lookup entirely — `config = secrets.github` regardless of what `organization` string is passed — so the signature check does not actually bind trust to the specific claimed repository owner at all in that mode [3](#0-2) .
3. `StatusHandler`'s params schema does not even require or use `repository` — it only requires `sha`/`state` and accepts `description`/`target_url`/`context`/`created_at`/`branches` [4](#0-3) .
4. `process` looks up commits **purely by SHA, globally across all stacks**, with zero repository/stack scoping: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [5](#0-4) .
5. `Commit#create_status_from_github!` calls `statuses.replicate_from_github!(stack_id, github_status)` using whatever `stack_id` the matched `Commit` row belongs to [6](#0-5) .
6. `Status.replicate_from_github!` persists `state`, `description`, `target_url`, `context`, `created_at` verbatim from the untrusted payload onto that `Status` row [7](#0-6) .
7. `target_url` is later rendered as a raw, unvalidated `href` in the commit status UI: `<a ... href="<%= status.target_url%>" target="_blank">` [8](#0-7)  and `<a href="<%= status.target_url %>" ...>` in the grouped view [9](#0-8) .

Root cause: nothing in this path checks that `params.repository.full_name` (or `repository_owner`) matches `commit.stack.repository.full_name`. Git SHAs are content-derived and public; an attacker with legitimate write access only to repository A (or their own repository, if it shares GitHub App installation scope/secret with repository B, e.g. same org install) can construct a commit object with an identical SHA to a public commit already tracked in stack B (reconstructing identical blobs/tree/parent/author/committer/message, which is fully mechanical since git objects are content-addressed and none of this requires any Shipit secret), set an arbitrary status on that commit via the normal GitHub Status API in their own repository, and have GitHub deliver a genuinely-signed `status` webhook to Shipit. `StatusHandler` then matches this SHA against `Commit` rows in **any** stack, including stack B, and writes the attacker's `target_url`/`description`/`context` there.

Existing guards do not stop this: `verify_signature` authenticates "a webhook signed with a Shipit-known secret," not "this specific repository/stack pairing"; the `ExplicitParameters` schema for `StatusHandler` never references `repository` to cross-check against the matched commit's stack.

### Impact Explanation
The attacker can write an arbitrary `target_url` (attacker-controlled URL, e.g. phishing/credential-harvesting page) rendered as a clickable link inside stack B's commit list UI, plus arbitrary `description`/`context`/`state`, for a repository/stack the attacker has no authorization over. This is a cross-tenant data-integrity violation: "a payload for one repository mutating another's stack/commit," matching the Critical category in scope. It also enables state confusion (marking a commit `success`/`failure`) which can influence `deployable?`/CI-gating logic on stack B (`Commit#deployable?` depends on `status`) — a further blast-radius concern beyond just the rendered URL. The attack is repeatable against any stack/commit whose SHA the attacker can reproduce, and scales to any stack sharing the relevant webhook trust boundary (same GitHub App/org secret).

### Likelihood Explanation
Preconditions: the attacker needs one genuinely GitHub-signed `status` webhook delivered to the same Shipit webhook endpoint/secret trust boundary that also covers stack B — realistic when a single GitHub App/org is used across many repositories/stacks (a very common Shipit deployment pattern, and made worse by the single-app config's `organization:` argument being ignored for secret lookup per `lib/shipit.rb:170-181`). Constructing an identical-SHA commit is mechanical for any public commit (deterministic content-addressed hashing) but requires the target commit's content/metadata to be knowable and requires the attacker to actually have some repository under the trusted webhook scope to emit from. No Shipit session, API token, or secret is required. This is a genuine code defect (missing repository binding) independent of how hard SHA reconstruction is in a given deployment.

### Recommendation
In `StatusHandler#process`, require and validate `repository.full_name` from the payload, and scope the `Commit` lookup to `Commit.joins(:stack).where(sha: params.sha, shipit_stacks: { repository_id: repository.id })` (or equivalent), rejecting/ignoring commits whose stack's repository does not match the webhook's declared repository. Additionally, bind `verify_signature` to the actual `repository.full_name`, not just `repository.owner.login`, and ensure `Shipit.github` does not silently ignore the `organization:` parameter in single-app configurations.

### Proof of Concept
```ruby
# test/models/webhooks/handlers/status_handler_test.rb (new)
test "status webhook writes attacker target_url onto a commit in an unrelated stack sharing the same sha" do
  victim_stack = shipit_stacks(:shipit)          # repo: shopify/shipit-engine
  attacker_stack = shipit_stacks(:cyclimse)      # unrelated repo: cyclimse/... 

  shared_sha = "deadbeef" * 5
  victim_commit = victim_stack.commits.create!(sha: shared_sha, ...)
  attacker_commit = attacker_stack.commits.create!(sha: shared_sha, ...) # attacker reproduces identical SHA in their own repo's history

  payload = {
    "sha" => shared_sha,
    "state" => "success",
    "target_url" => "https://attacker.example.com/phish",
    "context" => "ci/fake",
    "description" => "looks legit",
    "repository" => { "full_name" => "attacker/unrelated-repo", "owner" => { "login" => "attacker" } }
  }

  Shipit::Webhooks::Handlers::StatusHandler.new(payload).call

  victim_status = victim_commit.statuses.last
  assert_equal "https://attacker.example.com/phish", victim_status.target_url
  # Binding under test: victim_status.stack_id (victim_stack.id) must equal
  # the stack whose repository.full_name == payload["repository"]["full_name"] ("attacker/unrelated-repo") — it does NOT.
  refute_equal victim_stack.repository.full_name, payload["repository"]["full_name"]
end
``` [5](#0-4) [7](#0-6) [8](#0-7)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified

      Rails.logger.info([
        'WebhookController#verify_signature',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "signature=#{request.headers['X-Hub-Signature']}",
        "status=#{status}"
      ].join(' '))
```

**File:** lib/shipit.rb (L170-181)
```ruby
  def github(organization: github_default_organization)
    # Backward compatibility
    # nil signifies the single github app config schema is being used
    if github_default_organization.nil?
      config = secrets.github
    else
      config = github_app_config(organization)
      raise GithubOrganizationUnknown, organization if config.nil?
    end
    @github ||= {}
    @github[organization] ||= GitHubApp.new(organization, config)
  end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L7-18)
```ruby
        params do
          requires :sha, String
          requires :state, String
          accepts :description, String
          accepts :target_url, String
          accepts :context, String
          accepts :created_at, String

          accepts :branches, Array do
            requires :name, String
          end
        end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/status.rb (L24-33)
```ruby
      def replicate_from_github!(stack_id, github_status)
        find_or_create_by!(
          stack_id:,
          state: github_status.state,
          description: github_status.description,
          target_url: github_status.target_url,
          context: github_status.context,
          created_at: github_status.created_at
        )
      end
```

**File:** app/views/shipit/statuses/_status.html.erb (L1-1)
```erb
<a class="status status--<%= status.state %> <%= 'disabled' unless status.target_url.present? %>" <%= 'disabled' unless status.target_url.present? %> <% unless status.group? %>data-tooltip="<%= status.description.presence || status.state.capitalize %>"<% end %> href="<%= status.target_url%>" target="_blank">
```

**File:** app/views/shipit/statuses/_group.html.erb (L12-12)
```erb
        <a href="<%= status.target_url %>" <% unless status.target_url.present? %> disabled class="disabled" <% end %> target="_blank">
```
