### Title
Webhook signature verification keys off `repository.owner.login` while pull-request handlers act on the unrelated `repository.full_name` field, allowing an attacker's own org secret to authorize mutation of a victim repository's review stack - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb], [File: app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb])

### Summary
`WebhooksController#verify_signature` selects the HMAC secret using only `params.dig('repository','owner','login')`, but the pull-request handlers (e.g. `OpenedHandler`) look up the target `Shipit::Repository` using the independent `params.repository.full_name` field, and never check that `full_name` is consistent with `owner.login`. An attacker who legitimately administers `org-attacker` in a multi-tenant Shipit install (and therefore knows `org-attacker`'s real `webhook_secret`) can sign a payload whose `owner.login` is `org-attacker` but whose `repository.full_name` (and nested `pull_request.head.ref`/`sha`) point at `org-victim/app`, causing `ReviewStackAdapter#create!` to provision/mutate a review stack on the victim repository using attacker-chosen ref/sha.

### Finding Description
**Binding claimed to be broken:** `verified_repository_owner (params.dig('repository','owner','login'))` == `repository_full_name_used_for_mutation (params.repository.full_name)`.

Trace:
1. `WebhooksController#verify_signature` computes `repository_owner` strictly from `params.dig('repository','owner','login')` and fetches `github_app = Shipit.github(organization: repository_owner)`, verifying `X-Hub-Signature` against that org's `webhook_secret` [1](#0-0) [2](#0-1) .
2. Once verified, `create` simply parses `raw_post` and dispatches the full, attacker-controlled JSON to the relevant handlers without any re-check of `repository.full_name` against `repository.owner.login` [3](#0-2) .
3. `OpenedHandler#repository` resolves the target `Shipit::Repository` purely from `params.repository.full_name` via `Repository.from_github_repo_name`, a field that is never cross-validated against `owner.login` [4](#0-3) [5](#0-4) .
4. `ReviewStackAdapter#create!` then builds a `Stack` under that resolved repository's `review_stacks` scope using `branch: params.pull_request.head.ref` and stores `params.pull_request` (including `head.sha`) verbatim as the `github_pull_request` [6](#0-5) .

Because `owner.login` (used solely to select the signing secret) and `full_name` (used solely to select the mutated repository) are two independently attacker-controlled JSON fields in the same raw_post, an attacker who owns `org-attacker` (and thus legitimately knows its own `webhook_secret`) can:
- Set `repository.owner.login = "org-attacker"` so `verify_signature` fetches and validates against the attacker's own real secret.
- Set `repository.full_name = "org-victim/app"` and `pull_request.head.ref`/`pull_request.head.sha` to an attacker-chosen branch/commit.
- Send this as `X-Github-Event: pull_request`, `action: "opened"`, correctly HMAC-signed with `org-attacker`'s secret.

`ExplicitParameters` schema for `OpenedHandler` only requires `repository.full_name` to be a `String` — it enforces no relationship to the top-level owner used for signing [7](#0-6) . None of `drop_unhandled_event`, `check_if_ping`, or the `ExplicitParameters` schema perform this cross-check either.

### Impact Explanation
A request authenticated under `org-attacker`'s own webhook secret results in `Shipit::Repository` records belonging to `org-victim` having a new (or unarchived) `ReviewStack` created/mutated with an attacker-chosen `branch`/`ref`/`sha`, which subsequently gets queued for provisioning (`ReviewStackProvisioningQueue.add(stack)`) and eventually deployed/run through Shipit's task pipeline. This is a cross-tenant write: a payload authenticated for one repository/org mutates another repository's stack state and its provisioning/deploy pipeline — matching the Critical category "a payload for one repository mutating another's stack, commit, task or team." The attack is repeatable against any `org-victim/app` repository already registered in the shared Shipit instance, for as many PR numbers/environments as the attacker wants (`labeled`, `unlabeled`, `closed`, `reopened` handlers share the same `ReviewStackAdapter`/repository-resolution pattern and are equally exploitable).

### Likelihood Explanation
Preconditions: the Shipit instance must be configured for multiple GitHub organizations (multi-tenant `Shipit.github_apps` config) where the attacker legitimately controls at least one onboarded organization (`org-attacker`) and therefore knows its real `webhook_secret`; the victim repository (`org-victim/app`) must already exist as a `Shipit::Repository` with review stacks enabled/provisioning behavior satisfied. Attacker cost is trivial: no GitHub secrets, no Shipit session, no API token are required — only crafting a raw HTTP POST with a correctly computed sha1 HMAC using a secret the attacker already legitimately possesses. This is fully feasible and repeatable via direct requests to `POST /webhooks`, with no reliance on any GitHub-side validation since Shipit only checks the HMAC signature and never that the webhook actually originated from GitHub for the claimed repository.

### Recommendation
In `WebhooksController#verify_signature`, and/or centrally in `Handler`, require that `params.dig('repository','full_name')` deterministically maps to the same owner used to select the signing app (e.g., derive `repository_owner` from splitting `full_name` rather than a separate `owner.login` field, or assert `full_name.split('/').first == owner.login` before proceeding). Additionally, each handler (`OpenedHandler`, `ClosedHandler`, `LabeledHandler`, `UnlabeledHandler`, `ReopenedHandler`) should validate that the resolved `Shipit::Repository`'s owner matches the verified webhook organization before invoking `ReviewStackAdapter`.

### Proof of Concept
Minitest plan (`test/controllers/webhooks_controller_test.rb` style, no live GitHub):
```ruby
test "cross-tenant pull_request webhook mutates victim repository's stack" do
  victim_repo = shipit_repositories(:shipit) # owner: "org-victim", name: "app" (or create explicitly)
  attacker_secret = Shipit.github(organization: 'org-attacker').send(:webhook_secret) # attacker's own, legitimately known secret

  payload = {
    action: "opened",
    number: 999,
    pull_request: {
      id: 1, number: 999, url: "http://x", title: "t", state: "open",
      additions: 1, deletions: 0,
      head: { sha: "deadbeef" * 5, ref: "attacker-controlled-branch" },
      user: { login: "attacker" },
      assignees: [], labels: []
    },
    repository: { full_name: "org-victim/app", owner: { login: "org-attacker" } }, # MISMATCH
    sender: { login: "attacker" }
  }.to_json

  signature = "sha1=" + OpenSSL::HMAC.hexdigest("sha1", attacker_secret, payload)

  assert_no_difference -> { Shipit::ReviewStack.where(repository: victim_repo).count } do
    # EXPECTATION under correct binding: request must be rejected or must not
    # create/mutate a stack under org-victim/app.
    post shipit.webhooks_path, params: payload,
         headers: { 'X-Github-Event' => 'pull_request', 'X-Hub-Signature' => signature,
                    'Content-Type' => 'application/json' }
  end
  # If this assert_no_difference block fails (i.e. a ReviewStack IS created under
  # victim_repo with branch == "attacker-controlled-branch"), the binding
  # verified_repository_owner == repository_full_name_used_for_mutation is broken,
  # confirming the vulnerability.
end
```
Both sides of the binding checked: left side (`params.dig('repository','owner','login')`, used to select and validate against `org-attacker`'s secret) and right side (`params.repository.full_name`, used by `OpenedHandler#repository`/`ReviewStackAdapter#create!` to select and mutate `org-victim/app`'s `ReviewStack`) diverge with no code enforcing their equality, confirming the finding.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L33-35)
```ruby
            requires :repository do
              requires :full_name, String
            end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
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
