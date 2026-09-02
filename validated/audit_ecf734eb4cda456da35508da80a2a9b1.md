### Title
Webhook signature verification is keyed on `repository.owner.login`, but handler routing/mutation is keyed on the independent `repository.full_name` field, allowing cross-tenant Stack creation - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects the GitHub App/`webhook_secret` to check the HMAC against using `payload.dig('repository','owner','login')`, while every `PullRequest::*Handler` (e.g. `OpenedHandler`) resolves and mutates the target `Shipit::Repository` using the unrelated `payload.dig('repository','full_name')` field. Because these are two independent reads of an attacker-fully-controlled JSON body, a payload can be signed with Org A's own legitimate `webhook_secret` while its `repository.full_name` names Org B's tracked repository, causing the handler to create/provision a `ReviewStack` under Org B's `Repository` from a request that only Org A's credentials authenticated.

### Finding Description
The broken binding is: `Shipit.github(organization: payload.dig('repository','owner','login')).webhook_secret` (the key used to verify the HMAC) **must equal** the `webhook_secret`/org that owns `Shipit::Repository.from_github_repo_name(payload.dig('repository','full_name'))` (the record the handler mutates). Nothing in the code enforces this equality.

- `WebhooksController#verify_signature` (app/controllers/shipit/webhooks_controller.rb:24-49) computes `repository_owner` via `params.dig('repository','owner','login') || params.dig('organization','login')` (lines 59-62) and calls `Shipit.github(organization: repository_owner).verify_webhook_signature(signature, raw_post)`. This only decides *which org's secret* is used to validate the HMAC over the raw body — it never inspects `repository.full_name`. [1](#0-0) [2](#0-1) 

- After verification, `create` dispatches the parsed JSON straight to the handler chain: `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` (line 12), with no re-derivation or cross-check of the owner. [3](#0-2) 

- `PullRequest::OpenedHandler#repository` resolves the target repository solely from `params.repository.full_name`: `Shipit::Repository.from_github_repo_name(params.repository.full_name) || Shipit::NullRepository.new` (lines 50-54), and on `process` calls `ReviewStackAdapter.new(params, scope: repository.review_stacks).find_or_create!` (lines 41-46) — i.e. it creates a `Stack`/`ReviewStack` row scoped to whatever repository `full_name` names, independent of which org's key signed the request. [4](#0-3) 

- `Repository.from_github_repo_name` performs a plain `find_by(owner:, name:)` lookup split from the `full_name` string, with no relation back to the signing org at all: `repo_owner, repo_name = github_repo_name.downcase.split('/'); find_by(owner: repo_owner, name: repo_name)`. [5](#0-4) 

- `ReviewStackAdapter#create!` performs the actual mutation: it creates the `Stack`/`ReviewStack` row scoped to `repository.review_stacks` (the victim's `Repository`) using attacker-supplied `stack_attributes` (`branch: params.pull_request.head.ref`, `environment: "pr#{params.number}"`), and enqueues it for provisioning via `Shipit::ReviewStackProvisioningQueue.add(stack)`. [6](#0-5) 

**Attacker's request:** An attacker who legitimately owns an onboarded org/GitHub App on the same multi-tenant Shipit instance ("Org A", with a real, attacker-known `webhook_secret`) sends a `pull_request` `opened` event POST to `/webhooks` with:
```json
{
  "action": "opened",
  "number": 1,
  "pull_request": { "head": {"ref": "attacker-branch"}, "user": {"login": "attacker"}, "labels": [], ... },
  "repository": { "owner": {"login": "org-a"}, "full_name": "victim-org/victim-repo" },
  "sender": {"login": "attacker"}
}
```
and `X-Hub-Signature: sha1=<HMAC-SHA1(org_a_webhook_secret, raw_body)>`.

**Why guards fail:**
- `verify_signature` succeeds because `repository_owner == "org-a"`, and the attacker genuinely knows `org-a`'s `webhook_secret`, so `Shipit.github(organization: "org-a").verify_webhook_signature(...)` returns `true`.
- `drop_unhandled_event` passes because `pull_request` is a handled event.
- `ExplicitParameters` schema (`requires :repository do requires :full_name, String end`) only validates the *type* of `full_name`, not that it matches the signing owner.
- `GithubOrganizationUnknown` handling is irrelevant since `org-a` is a known, legitimately configured organization.
- No code anywhere compares `params.dig('repository','owner','login')` to the owner segment of `params.dig('repository','full_name')`.

### Impact Explanation
The attacker causes creation (and provisioning enqueue) of a `Shipit::ReviewStack`/`Stack` row under a *victim* organization's tracked `Shipit::Repository`, authenticated only by the attacker's own org's webhook secret — a payload for one repository (org-a's) mutating another repository's (`victim-org/victim-repo`) stack state, matching the Critical category "a payload for one repository mutating another's stack, commit, task or task or team." This is repeatable against any tracked repository whose `owner/name` the attacker can guess or discover (repository names/orgs are typically public on GitHub), for any handler that keys off `repository.full_name` (`OpenedHandler`, `ClosedHandler`, `LabeledHandler`, `UnlabeledHandler`, `ReopenedHandler`, `EditedHandler`, `LabelCapturingHandler`, and the generic `Handler#stacks`/`push`/`status` handling), giving broad cross-tenant blast radius across the whole multi-org install: archiving/unarchiving/provisioning review stacks, updating pull-request metadata, or affecting commit statuses belonging to repositories the attacker never authenticated against.

### Likelihood Explanation
Requires a Shipit deployment that hosts multiple organizations/GitHub Apps with independent `webhook_secret`s sharing one `/webhooks` endpoint (a realistic multi-tenant configuration, since `Shipit.github(organization:)` explicitly supports per-org config lookups and `GithubOrganizationUnknown` handling exists precisely for this multi-org case). Attacker cost is low: they only need to control one legitimately onboarded org (their own) and craft an arbitrary JSON body with a mismatched `repository.owner.login` vs. `repository.full_name`, both attacker-controlled fields in the raw POST body, then sign it with their own known secret. No GitHub-side involvement or spoofing of GitHub's real webhook delivery is needed — the attacker POSTs directly to the Shipit host. The attack is fully repeatable against any other tracked repository.

### Recommendation
In `WebhooksController#verify_signature`, derive the organization used to select the signing key from the *same* field the handlers use to identify the target repository (i.e. use `payload.dig('repository', 'full_name')`'s owner segment, not `payload.dig('repository','owner','login')`), or explicitly assert that `repository.owner.login` matches the owner segment of `repository.full_name` before proceeding, rejecting the request (422) on mismatch. Ensure this same repository identity is threaded through consistently to the handlers so the org that signed the payload is provably the org whose `Repository` row gets mutated.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb
test "signature verified against org A's secret cannot mutate org B's tracked repository" do
  # Org A ("attacker-org") and Org B ("victim-org") are both configured in Shipit.github_configs
  # with distinct webhook_secrets; Org B owns a tracked Shipit::Repository "victim-org/victim-repo"
  # that has review_stacks_enabled + provisioning_behavior_allow_all.
  victim_repository = shipit_repositories(:victim_repo) # owner: "victim-org", name: "victim-repo"

  body = {
    action: "opened",
    number: 1,
    pull_request: {
      id: 1, number: 1, url: "https://api.github.com/...", title: "x", state: "open",
      additions: 1, deletions: 0,
      head: { sha: "a" * 40, ref: "attacker-branch" },
      user: { login: "attacker" },
      assignees: [], labels: []
    },
    repository: { owner: { login: "attacker-org" }, full_name: "victim-org/victim-repo" },
    sender: { login: "attacker" }
  }.to_json

  # Signature computed with Org A's (attacker-org's) OWN, legitimately-known webhook_secret.
  signature = "sha1=" + OpenSSL::HMAC.hexdigest("sha1", Shipit.github(organization: "attacker-org").send(:webhook_secret), body)

  request.headers["X-Github-Event"] = "pull_request"
  request.headers["X-Hub-Signature"] = signature

  assert_no_difference -> { Shipit::Stack.count.with(repository: victim_repository) } do
    post :create, body: body, as: :json
    assert_response :ok # verification passes (signed by attacker-org), yet handler targets victim-org's repo
  end
  # EXPECTED (secure): assertion above holds — no stack created under victim's repository.
  # ACTUAL (vulnerable): a Shipit::ReviewStack is created under victim_repository.review_stacks,
  # proving cross-tenant mutation authenticated only by attacker-org's own webhook_secret.
end
```
Both sides of the claimed binding — "org whose secret verified the body" (`attacker-org`) vs. "org owning the mutated `Repository`" (`victim-org`) — diverge after tracing the code, confirming the vulnerability.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-54)
```ruby
          def process
            return unless respond_to_pull_request_opened?

            Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks).find_or_create!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
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

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L72-94)
```ruby
          def create!
            ReviewStack.transaction do
              stack = scope.create!(stack_attributes)
              stack
                .build_pull_request
                .update!(
                  github_pull_request: params.pull_request
                )
            end

            Shipit::ReviewStackProvisioningQueue.add(stack)

            @stack = stack
          end

          def stack_attributes
            {
              branch: params.pull_request.head.ref,
              environment:,
              ignore_ci: false,
              continuous_deployment: false
            }
          end
```
