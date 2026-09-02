### Title
Webhook signature verification uses `repository.owner.login` while handlers resolve stacks via a separately-controlled `repository.full_name`, allowing cross-tenant stack `archive!`/`unarchive!` - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb])

### Summary
`WebhooksController#verify_signature` selects the HMAC secret to validate the request using `params.dig('repository','owner','login')`, but `LabeledHandler`/`UnlabeledHandler` resolve the target repository using the independent field `params.repository.full_name` via `Shipit::Repository.from_github_repo_name`. Because both fields are attacker-supplied within the same raw JSON body of a direct POST to `/webhooks`, and nothing cross-validates that `repository.owner.login` matches the owner embedded in `repository.full_name`, an attacker who knows a webhook secret for org-a can sign a payload whose `repository.owner.login` is `"org-a"` (so the correct/known secret is selected) while `repository.full_name` names an org-b repository, causing `stack.archive!`/`stack.unarchive!` to execute against org-b's live `ReviewStack`.

### Finding Description
The claimed binding should be: `organization used to select webhook_secret in verify_signature == organization owning the repository/stack mutated in the handler`. Tracing the code shows this binding is never enforced:

- `WebhooksController#verify_signature` picks the GitHub App/secret via `repository_owner`, defined as `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` [1](#0-0) [2](#0-1) .
- `LabeledHandler#repository` (and `UnlabeledHandler#repository`) instead resolve the repository from a *different* field, `params.repository.full_name`, via `Shipit::Repository.from_github_repo_name` [3](#0-2) .
- `Repository.from_github_repo_name` simply splits `"owner/name"` and does a DB lookup — it performs no comparison against the JSON's `repository.owner.login` field [4](#0-3) .
- `handle` then unconditionally calls `stack.archive!`/`stack.unarchive!` on the `ReviewStackAdapter` built from that resolved repository's `review_stacks`, based purely on payload-controlled label names [5](#0-4) .

Because this is a direct HTTP POST to `/webhooks` crafted by the attacker (not a relayed genuine GitHub event), the attacker fully controls both the `repository.owner.login` sub-field (used only for secret selection) and the top-level `repository.full_name` field (used only for repository/stack resolution) inside the same raw body they sign. `verify_signature` never checks that these two independently-read fields refer to the same organization/repository. An attacker who owns org-a and therefore knows org-a's `webhook_secret` can set `repository.owner.login = "org-a"` (to make `verify_webhook_signature` select and validate against org-a's known secret) while setting `repository.full_name = "org-b/repo"` (to make `LabeledHandler#repository` resolve org-b's real `Repository`/`ReviewStack`). No other guard intervenes: `drop_unhandled_event` only checks the event type header, `ExplicitParameters` (`params do ... end`) only validates types/presence of fields, not cross-field/owner consistency, and there is no `require_permission!`/session check on this unauthenticated webhook endpoint.

### Impact Explanation
A successful request causes `Shipit::ReviewStack#archive!` or `#unarchive!` to run against org-b's infrastructure-backed review stack — a live deployment lifecycle mutation for a repository the attacker never authenticated against. This is repeatable against any repository/organization the attacker can guess or discover the `full_name` of (repository full names are generally public), as long as the target has `review_stacks_enabled` and a `provisioning_label_name` configured, and a live review stack exists for the targeted PR number. This matches the Critical category: "a payload for one repository mutating another's stack" — cross-tenant unauthorized stack lifecycle mutation.

### Likelihood Explanation
Preconditions are modest and plausible: attacker must control/own at least one org (org-a) onboarded to this Shipit instance (to know its `webhook_secret`), and the victim org-b repo must have `review_stacks_enabled` with `provisioning_behavior_prevent_with_label` (or `allow_with_label`) and a live `ReviewStack` for a real PR number. The attack requires no GitHub relay — the attacker sends a raw HTTP POST directly to the Shipit `/webhooks` endpoint with a self-crafted JSON body and a self-computed HMAC signature using their own known secret, which is straightforward and fully repeatable.

### Recommendation
In `WebhooksController#verify_signature`, and/or in each handler's `repository` resolution, enforce that the organization used to select the webhook secret is the same organization embedded in `repository.full_name` (e.g., derive `repository_owner` solely from `repository.full_name`'s owner segment, or explicitly assert `params.dig('repository','owner','login') == params.repository.full_name.split('/').first` before dispatching to handlers) so that a verified payload cannot reference infrastructure belonging to a different organization than the one whose secret validated it.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (new test)
test "labeled webhook with mismatched repository.owner.login and repository.full_name archives another org's stack" do
  org_a_repo = shipit_repositories(:shipit) # attacker's own onboarded repo, owner "org-a"
  org_b_repo = create_repository(owner: "org-b", name: "victim", review_stacks_enabled: true,
                                  provisioning_behavior: "prevent_with_label", provisioning_label_name: "no-deploy")
  review_stack = create_review_stack(repository: org_b_repo, pull_request_number: 42) # live, unarchived

  payload = {
    action: "labeled",
    number: 42,
    pull_request: {
      id: 1, number: 42, url: "...", title: "t", state: "open",
      additions: 1, deletions: 1,
      head: { sha: "abc", ref: "branch" },
      user: { login: "attacker" },
      assignees: [],
      labels: [{ name: "no-deploy" }]
    },
    repository: {
      full_name: "org-b/victim",       # target: victim org's repo
      owner: { login: "org-a" }        # used only for signature secret selection
    },
    sender: { login: "attacker" }
  }.to_json

  signature = "sha1=" + OpenSSL::HMAC.hexdigest("sha1", org_a_webhook_secret, payload)

  assert_not review_stack.reload.archived_since?

  post "/webhooks", params: payload, headers: {
    "X-Github-Event" => "pull_request",
    "X-Hub-Signature" => signature,
    "Content-Type" => "application/json"
  }

  assert_response :ok
  assert review_stack.reload.archived_since?, "org-b's review stack was archived by a payload validated with org-a's secret"
end
```
This demonstrates: signature validated using org-a's known secret (via `repository.owner.login = "org-a"`), yet the handler mutates org-b's `ReviewStack` (resolved via the independent `repository.full_name = "org-b/victim"`), proving the two values that should be bound are not, and asserting the state change on the victim's side.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L49-63)
```ruby
          def handle
            if archive?
              stack.archive!
            elsif unarchive?
              stack.unarchive!
            end

            stack
          end

          def stack
            @stack ||=
              Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks)
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L65-68)
```ruby
          def repository
            @repository ||= Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
                            Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
