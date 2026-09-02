### Title
Cross-repository `github_pull_request` write via org-mismatched `pull_request.assigned`/`unassigned` webhook - ([File: app/models/shipit/webhooks/handlers/pull_request/assigned_handler.rb])

### Summary
`WebhooksController#verify_signature` authenticates a webhook only against the organization named in `params.dig('repository','owner','login')`, selecting the `GithubApp`/secret for that org via `Shipit.github(organization: repository_owner)`. `AssignedHandler`, however, resolves the target `Repository`/`PullRequest` using the separate, independently-controlled `repository.full_name` field from the same unsigned-relative-to-that-binding JSON body, with no check that `full_name`'s owner matches the verified `repository_owner`.

### Finding Description
The broken binding: `repository_owner` (`params.dig('repository','owner','login')`, used to select the signing secret in `Shipit::WebhooksController#verify_signature`, [1](#0-0) , org selection at [2](#0-1) ) is never checked to equal the org embedded in `params.repository.full_name`, which is what `AssignedHandler#repository` actually uses to resolve the row to mutate: [3](#0-2) . Both `owner.login` and `full_name` are independent, attacker-supplied fields inside the same JSON payload; nothing in `ExplicitParameters` schema, `Repository.from_github_repo_name`, or `Handler` enforces `full_name.split('/').first == owner.login`.

`Shipit.github(organization:)` returns a distinct `GithubApp` (and distinct `webhook_secret`) per configured organization. If Shipit is configured to serve multiple organizations, and any one of them (an org the attacker legitimately administers, e.g. their own onboarded org) has a webhook secret the attacker knows (because they configured that org's GitHub webhook themselves), the attacker can:
1. Set `repository.owner.login` = their own org (`attacker-org`), so `verify_signature` selects `Shipit.github(organization: 'attacker-org')` and successfully verifies the HMAC computed with their known secret over the exact raw body they send.
2. Set `repository.full_name` = `victim-org/victim-repo` (any repository already tracked by Shipit) and `number` = an existing victim `PullRequest#number`.
3. Set `action` = `"assigned"` or `"unassigned"`, and craft `pull_request.assignees` arbitrarily.

`AssignedHandler#process` then finds the victim's real `Shipit::Repository` via `Repository.from_github_repo_name(params.repository.full_name)`, looks up the victim `PullRequest` via `Shipit::PullRequest.joins(:stack, stack: :repository).find_by(number:, stacks: {repositories: {id: repository.id}})`, and calls `pull_request.update(github_pull_request: params.pull_request)` [4](#0-3)  — mutating a row belonging to a repository/org the attacker never authenticated as.

None of the existing guards stop this: `verify_signature` only proves the sender knows the secret for whatever org is named in `owner.login`, not for the org named in `full_name`; `drop_unhandled_event` only checks the event type exists; the `ExplicitParameters` schema for `AssignedHandler` only requires `repository.full_name` to be a `String`, with no relational check against `owner.login`.

### Impact Explanation
The attacker can overwrite `github_pull_request` (title, state, assignees, labels payload, etc.) on any `Shipit::PullRequest` row for any repository/stack tracked by the target Shipit instance, as long as they can get one org's webhook secret verified against their own crafted body. Downstream, `github_pull_request` data feeds review-stack/deploy-gating logic (`ReviewStackAdapter`, PR serializers) — this is a cross-tenant write triggered by a payload that "verified" a completely different organization than the one whose data got mutated, matching the Critical category "a payload for one repository mutating another's stack/commit/task" pattern, though scoped here to PR metadata specifically (mapped as High per the question's framing). It is repeatable against any repository number combination as long as the attacker can produce one valid signature for any onboarded org.

### Likelihood Explanation
This requires the attacker to possess a valid webhook secret for at least one organization configured in `Shipit.github`. In the single-tenant deployment model (one Shipit instance per GitHub org, one secret), this is not exploitable by an external, fully unprivileged attacker, since they'd need the operator's own webhook secret. But in any Shipit deployment configured for multiple organizations (`Shipit.github_teams`/multi-org GithubApp config), a user who legitimately administers or is granted admin on one of those onboarded orgs (and thus knows/sets that org's webhook secret when wiring the GitHub webhook) can trivially forge cross-org payloads targeting any other onboarded repository — no GitHub-side webhook delivery is needed since `POST /webhooks` is a public, directly reachable endpoint. This is plausible but depends on multi-org configuration, which cannot be fully confirmed as a mandatory deployment shape here.

### Recommendation
In `WebhooksController#verify_signature` or in `Shipit::Webhooks::Handlers::Handler`, enforce that the organization used to select the verifying `GithubApp`/secret matches the organization embedded in `params.repository.full_name` before any handler runs (e.g., reject if `repository_owner.downcase != full_name.split('/').first.downcase`). Alternatively, have handlers resolve the repository from the verified `repository_owner` rather than trusting `full_name` independently.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (new test)
test "assigned webhook verified for one org cannot mutate PullRequest of a different org's repository" do
  victim_repo = shipit_repositories(:shipit) # owner: "shopify", tracked repo
  victim_pr = shipit_pull_requests(:review_stack_review)
  victim_pr.update!(number: 4242)

  attacker_org = "attacker-org"
  Shipit.stubs(:github).with(organization: attacker_org).returns(
    Shipit::GithubApp.new(attacker_org, webhook_secret: "attacker_known_secret")
  )

  body = {
    action: "assigned",
    number: victim_pr.number,
    pull_request: {
      id: 1, number: victim_pr.number, url: "https://x", title: "hijacked",
      state: "open", additions: 1, deletions: 1,
      head: { sha: "a" * 40, ref: "feature" },
      user: { login: "attacker" },
      assignees: [{ login: "attacker" }],
      labels: []
    },
    repository: { full_name: victim_repo.github_repo_name, owner: { login: attacker_org } },
    sender: { login: "attacker" }
  }.to_json

  signature = "sha1=" + OpenSSL::HMAC.hexdigest("sha1", "attacker_known_secret", body)

  @request.headers["X-Github-Event"] = "pull_request"
  @request.headers["X-Hub-Signature"] = signature

  post :create, body: body, as: :json

  assert_response :ok
  assert_equal "attacker", victim_pr.reload.github_pull_request["user"]["login"]
  # asserts binding is broken: verified org (attacker-org) != repository.id's org (shopify)
  # yet the victim's PullRequest row was updated.
end
```

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

**File:** app/models/shipit/webhooks/handlers/pull_request/assigned_handler.rb (L41-45)
```ruby
          def process
            return unless respond_to_assignee_change?

            pull_request.update(github_pull_request: params.pull_request) if pull_request.present?
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/assigned_handler.rb (L67-69)
```ruby
          def repository
            Shipit::Repository.from_github_repo_name(params.repository.full_name) || Shipit::NullRepository.new
          end
```
