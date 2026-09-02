### Title
Webhook signature verification binds to `repository.owner.login`, but provisioning decisions bind to `repository.full_name` — cross-repository review-stack forgery - ([File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb], [File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to verify the HMAC against using `params.dig('repository','owner','login')`, while `OpenedHandler#repository` / `LabelCapturingHandler#repository` resolve the actual `Shipit::Repository` (and thus the `provisioning_behavior_*`/`provisioning_label_name` config that gates `ReviewStackAdapter#find_or_create!`) using the independent `params.repository.full_name` field. No code anywhere checks that these two identify the same repository/owner, so a payload validated under one tenant's (weak or unset) signing config can drive provisioning decisions and create a `ReviewStack` on a completely different, victim repository.

### Finding Description
Broken binding (should hold, but doesn't):
`Shipit.github(organization: params.dig('repository','owner','login'))` used to verify the signature (`app/controllers/shipit/webhooks_controller.rb:24-49`, `repository_owner` at line 59-62) **==** `Shipit::Repository.from_github_repo_name(params.repository.full_name)` used to gate provisioning (`app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb:50-54`, `app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb:110-114`).

These two lookups draw from two different JSON fields of the *same attacker-supplied payload* with no cross-check: [1](#0-0) [2](#0-1) [3](#0-2) 

`lib/shipit/github_app.rb#verify_webhook_signature` additionally short-circuits to `true` when the selected org has no configured `webhook_secret` — an explicitly documented "optional" field in `docs/setup.md` ("Webhook secret (optional)"): [4](#0-3) 

Exploit flow: an attacker who is a tenant admin of any org registered in Shipit's multi-tenant `github:` config that has left `webhook_secret` blank (this codebase explicitly supports multiple orgs sharing one Shipit host, see `test/dummy/config/secrets_double_github_app.yml`) sends a raw `POST /webhooks` with `X-Github-Event: pull_request` and a JSON body where `repository.owner.login = "attacker-org"` (secretless, so `verify_signature` passes trivially) but `repository.full_name = "victim-org/victim-repo"`. `OpenedHandler#repository` resolves the real `victim-org/victim-repo` `Repository` record via `from_github_repo_name`, and `provision?` is evaluated against that record's real `provisioning_behavior_*`/`provisioning_label_name`, using `pull_request.labels` and `pull_request.head.ref` that are entirely attacker-controlled JSON, not anything actually posted on the victim's real GitHub repository. `ReviewStackAdapter#find_or_create!`/`create!` then creates a real `ReviewStack` scoped to `repository.review_stacks` (the victim's actual repository) with attacker-chosen `branch`/`environment`. [5](#0-4) 

No guard (`ExplicitParameters` schema, `drop_unhandled_event`, model validations) checks that `repository.owner.login` matches the owner segment of `repository.full_name`; both are free-form strings validated only for basic format, not cross-consistency.

### Impact Explanation
This is a payload nominally authenticated "for" one repository/organization mutating and provisioning a review stack for a completely different, victim repository/tenant — matching the Critical category "a payload for one repository mutating another's stack." Any tenant (or knowledge of any tenant) in the shared multi-org Shipit instance that has an unset `webhook_secret` becomes a skeleton key to forge provisioning events against every other repository registered on the same Shipit host, bypassing `provisioning_behavior_prevent_with_label?`/`allow_with_label?` gates entirely, since the labels and branch used in the decision are 100% attacker-authored JSON, not anything that ever existed on the victim's GitHub repo.

### Likelihood Explanation
Requires: (1) a shared, multi-tenant Shipit deployment (explicitly supported, see `Shipit.github(organization:)` and `test/dummy/config/secrets_double_github_app.yml`), and (2) at least one org in that deployment with `webhook_secret` left blank (documented as optional). No GitHub secrets, sessions, or API tokens are needed — only an HTTP client capable of `POST /webhooks`. This is highly feasible in real deployments since `webhook_secret` is optional and easy to overlook, and is fully repeatable against any repository name the attacker can guess/know.

### Recommendation
Cross-validate that the owner used for signature verification (`repository.owner.login`) matches the owner segment of `repository.full_name` before dispatching to handlers, and reject the payload otherwise. Additionally, always require a `webhook_secret` to be configured per tenant (fail closed rather than `return true unless webhook_secret`).

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_cross_repo_test.rb
test "pull_request payload with mismatched repository.owner.login and repository.full_name provisions victim repo" do
  attacker_org_config = { 'webhook_secret' => nil } # secretless tenant
  Shipit.stubs(:github).with(organization: 'attacker-org').returns(Shipit::GithubApp.new('attacker-org', attacker_org_config))

  victim_repo = shipit_repositories(:shipit) # e.g. owner: 'victim-org', name: 'victim-repo'
  victim_repo.update!(provisioning_behavior: 'prevent_with_label', provisioning_label_name: 'no-deploy')

  request.headers['X-Github-Event'] = 'pull_request'
  body = {
    action: 'opened',
    number: 999,
    pull_request: {
      id: 1, number: 999, url: 'https://x', title: 't', state: 'open',
      additions: 1, deletions: 0,
      head: { sha: 'abc', ref: 'attacker-branch' },
      user: { login: 'attacker' },
      assignees: [],
      labels: [] # no 'no-deploy' label -> provision? true under prevent_with_label
    },
    repository: { owner: { login: 'attacker-org' }, full_name: victim_repo.github_repo_name },
    sender: { login: 'attacker' }
  }.to_json

  assert_difference -> { victim_repo.review_stacks.count }, 1 do
    post :create, body:, as: :json
  end
end
```
Both sides of the binding: `repository_owner` = `"attacker-org"` (used to select signing authority) vs. resolved `Repository` = `victim-org/victim-repo` (used to gate provisioning) — they diverge, and the request still succeeds in creating a `ReviewStack` on the victim repository, proving the vulnerability.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-78)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end

          def pull_request
            params.pull_request
          end

          def respond_to_pull_request_opened?
            params.action == "opened" &&
              provision?
          end

          def provision?
            repository.review_stacks_enabled &&
              repository.provisioning_behavior_allow_all? ||
              (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
          end

          def pull_request_has_provisioning_label?
            pull_request_label_names.include?(repository.provisioning_label_name)
          end

          def pull_request_label_names
            Array.new(pull_request["labels"]).map { |label| label["name"] }
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

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L72-98)
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

          def environment
            "pr#{params.number}"
          end
```
