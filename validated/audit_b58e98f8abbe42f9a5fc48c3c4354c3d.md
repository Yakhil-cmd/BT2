### Title
Forged `pull_request`/`unassigned` webhook using an org with no `webhook_secret` lets an attacker mutate an unrelated repository's PullRequest record - (File: app/controllers/shipit/webhooks_controller.rb, app/models/shipit/webhooks/handlers/pull_request/assigned_handler.rb)

### Summary
`Shipit::WebhooksController#verify_signature` selects which GitHub App/org config to use for HMAC verification solely from `params.dig('repository','owner','login')`, and `GitHubApp#verify_webhook_signature` returns `true` unconditionally when that org's config has no `webhook_secret` configured. Because the handler that actually mutates state (`AssignedHandler`) independently resolves the target repository from the unrelated field `params.repository.full_name`, an attacker can pick a no-secret org for the signature-check field while pointing the mutation at a victim repository belonging to a different, secret-protected org.

### Finding Description
The broken binding, stated as an equality that the code assumes but never enforces:

`org_used_for_signature_verification (params.repository.owner.login)` == `org_that_actually_owns_the_mutated_repository (params.repository.full_name's owner)`

In a genuine GitHub webhook these two are always the same repository/org, but nothing in the code ties them together — they are two independently-read fields of an attacker-controlled JSON body.

Path:
1. `POST /webhooks` → `WebhooksController#create` (`app/controllers/shipit/webhooks_controller.rb:10`) runs `before_action :verify_signature`.
2. `verify_signature` computes `repository_owner` from `params.dig('repository','owner','login')` [1](#0-0)  and fetches `Shipit.github(organization: repository_owner)`, then calls `github_app.verify_webhook_signature(...)` [2](#0-1) .
3. `GitHubApp#verify_webhook_signature` returns `true` immediately if `webhook_secret` is blank for that org's config — no HMAC is checked at all [3](#0-2) .
4. Once verification passes, `create` fans the *same raw params* out to every registered `pull_request` handler via `Shipit::Webhooks.for_event(event)` [4](#0-3) [5](#0-4) .
5. `Handlers::PullRequest::AssignedHandler` runs for both `assigned` and `unassigned` actions (`respond_to_assignee_change?` checks `%w[assigned unassigned]`) [6](#0-5) , and resolves the target repository using `params.repository.full_name`, completely independent of the `repository.owner.login` field used for signature selection [7](#0-6) . It then looks up the matching `Shipit::PullRequest` by `number` + that repository and calls `pull_request.update(github_pull_request: params.pull_request)` [8](#0-7) .

Exploit request: attacker POSTs a JSON body with `X-Github-Event: pull_request`, no valid `X-Hub-Signature` (or an arbitrary garbage one), and body:
```json
{
  "action": "unassigned",
  "number": <victim PR number>,
  "repository": { "owner": { "login": "attacker-controlled-no-secret-org" }, "full_name": "victim-org/victim-repo" },
  "pull_request": { ... attacker-chosen fields ... },
  "sender": { "login": "attacker" }
}
```
Provided `attacker-controlled-no-secret-org` is any org configured in Shipit (`Shipit.github_config`/`Shipit.github`) without a `webhook_secret`, `verify_signature` passes unconditionally, and `AssignedHandler` writes attacker-supplied `github_pull_request` data onto the victim repo's `PullRequest` row identified by `full_name: "victim-org/victim-repo"` and `number`.

Existing guards checked and why they don't help: `drop_unhandled_event` only filters unregistered event types, not actions, so `unassigned` reaches `AssignedHandler`. `ExplicitParameters` (`params do ... end` blocks) only validate the shape/types of fields, not cross-field consistency between `repository.owner.login` and `repository.full_name`. There is no `require_permission!`/session check since this is an unauthenticated webhook endpoint by design; the only intended protection is HMAC signature verification, which is defeated by choosing a no-secret org for the `owner.login` field.

### Impact Explanation
An unprivileged internet attacker can write attacker-chosen `github_pull_request` fields (title, state, additions/deletions, head sha/ref, assignees, labels) onto a `Shipit::PullRequest` record belonging to any victim repository/stack that has a matching PR `number`, as long as any org configured in Shipit lacks a `webhook_secret`. This is a payload for one repository/org mutating another repository's stack/PR state, matching the Critical category "a payload for one repository mutating another's stack, commit, task or team." The same root cause (mismatched `repository.owner.login` vs. `repository.full_name`) generically applies to every PR handler that resolves its target repository from `full_name` rather than from the org used to authenticate the request (e.g. `LabelCapturingHandler`), so the blast radius extends to label/review-stack state as well. Repeatable per request, against any repository with a PR number known/guessed by the attacker.

### Likelihood Explanation
Preconditions: (1) at least one GitHub organization is configured in Shipit's `github` config without a `webhook_secret` (a realistic misconfiguration/legacy-config scenario explicitly anticipated by the `return true unless webhook_secret` short-circuit in the code itself); (2) attacker knows or guesses a target repository `full_name` and PR `number` (both are low-entropy/public information for public repos). No secrets, sessions, or GitHub App credentials are required — a bare unauthenticated `POST /webhooks` suffices, so cost is minimal and the attack is fully repeatable.

### Recommendation
Bind the signature-verification org to the org actually used by the mutation path: derive `repository_owner` from `params.repository.full_name`'s owner (or equivalently validate that `params.repository.owner.login` matches the owner segment of `params.repository.full_name`) before dispatching to handlers, and reject the request if they diverge. Additionally, treat a blank `webhook_secret` as "verification not configured" rather than "verification passes," e.g. reject (or require an explicit opt-in flag) when `webhook_secret` is absent for a configured org, instead of returning `true` unconditionally in `GitHubApp#verify_webhook_signature`.

### Proof of Concept
minitest plan (no live GitHub calls needed):
```ruby
test "unassigned pull_request webhook from a no-secret org mutates a PR owned by a different, secret-protected org" do
  # Arrange: stub Shipit.github_config / Shipit.github so org "no-secret-org" has no webhook_secret,
  # while "victim-org" has a configured webhook_secret.
  victim_repo = shipit_repositories(:shipit) # full_name e.g. "victim-org/victim-repo"
  stack = victim_repo.stacks.first
  pr = create_pull_request(stack: stack, number: 42, github_pull_request: { "labels" => [] })

  before_title = pr.github_pull_request["title"]

  payload = {
    action: "unassigned",
    number: 42,
    repository: { owner: { login: "no-secret-org" }, full_name: victim_repo.full_name },
    pull_request: {
      id: 1, number: 42, url: "http://x", title: "ATTACKER-INJECTED-TITLE",
      state: "open", additions: 1, deletions: 0,
      head: { sha: "a" * 40, ref: "feature" },
      user: { login: "attacker" }, assignees: [], labels: []
    },
    sender: { login: "attacker" }
  }.to_json

  post "/webhooks", params: payload,
       headers: { "X-Github-Event" => "pull_request", "X-Hub-Signature" => "sha1=deadbeef", "Content-Type" => "application/json" }

  assert_response :ok
  pr.reload
  # Equality broken: attacker who never held victim-org's webhook_secret still mutated victim-org's PullRequest.
  refute_equal before_title, pr.github_pull_request["title"]
  assert_equal "ATTACKER-INJECTED-TITLE", pr.github_pull_request["title"]
end
```
This demonstrates that `repository_owner ("no-secret-org")` used for signature verification does not equal the owner of `params.repository.full_name ("victim-org/victim-repo")` whose `PullRequest` was actually mutated, proving the cross-tenant write.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-30)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** app/models/shipit/webhooks.rb (L9-18)
```ruby
          'pull_request' => [
            Handlers::PullRequest::OpenedHandler,
            Handlers::PullRequest::ClosedHandler,
            Handlers::PullRequest::ReopenedHandler,
            Handlers::PullRequest::EditedHandler,
            Handlers::PullRequest::AssignedHandler,
            Handlers::PullRequest::LabeledHandler,
            Handlers::PullRequest::UnlabeledHandler,
            Handlers::PullRequest::LabelCapturingHandler
          ],
```

**File:** app/models/shipit/webhooks/handlers/pull_request/assigned_handler.rb (L41-65)
```ruby
          def process
            return unless respond_to_assignee_change?

            pull_request.update(github_pull_request: params.pull_request) if pull_request.present?
          end

          private

          def respond_to_assignee_change?
            %w[assigned unassigned].include?(params.action)
          end

          def pull_request
            @pull_request ||= Shipit::PullRequest
                              .joins(:stack, stack: :repository)
                              .find_by(
                                number: params.number,
                                stacks: {
                                  repositories:
                                    {
                                      id: repository.id
                                    }
                                }
                              )
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/assigned_handler.rb (L67-69)
```ruby
          def repository
            Shipit::Repository.from_github_repo_name(params.repository.full_name) || Shipit::NullRepository.new
          end
```
