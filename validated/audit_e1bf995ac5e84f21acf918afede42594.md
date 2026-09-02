### Title
Signature verification keyed on `repository.owner.login` while handlers act on unchecked `repository.full_name` allows cross-tenant stack mutation - (File: app/controllers/shipit/webhooks_controller.rb, app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb)

### Summary
`WebhooksController#verify_signature` selects the GitHub App / `webhook_secret` to verify against using `params.dig('repository','owner','login')`, but `ReopenedHandler#repository` looks up the target `Shipit::Repository` using the independent field `params.repository.full_name`. Nothing enforces that these two fields describe the same repository, so a payload signed with one tenant's `webhook_secret` can name a different tenant's repository as the mutation target.

### Finding Description
The broken binding: `repository_owner (used to select webhook_secret)` == `owner(repository.full_name) (used to select the mutated Repository/ReviewStack)`. This equality is never checked.

Path:
1. `WebhooksController#verify_signature` computes `github_app = Shipit.github(organization: repository_owner)` where `repository_owner = params.dig('repository','owner','login')`, then verifies `X-Hub-Signature` against that org's `webhook_secret` [1](#0-0) .
2. `Shipit.github(organization:)` resolves a distinct `GitHubApp` (and distinct `webhook_secret`) per organization key in `secrets.github` in multi-tenant configurations [2](#0-1) .
3. Once the signature passes for the resolved org, the raw JSON body is dispatched unmodified to handlers: `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [3](#0-2) .
4. `ReopenedHandler#repository` resolves the target repository purely from `params.repository.full_name`, with no reference to `params.repository.owner.login`: `Shipit::Repository.from_github_repo_name(params.repository.full_name)` [4](#0-3) .
5. `Repository.from_github_repo_name` simply splits the string on `/` and does a DB lookup, with no cross-check against any authenticated identity [5](#0-4) .
6. `stack.unarchive!` is then invoked on the resolved repository's review stack in `process` [6](#0-5) .

Exploit flow: In a Shipit deployment configured for multiple GitHub organizations/tenants (each with its own App and `webhook_secret`, as supported by `github_app_config`), an attacker who legitimately controls one tenant (e.g., has a repo/org `attacker-org` with a Shipit GitHub App installed) knows `attacker-org`'s `webhook_secret` because it's their own GitHub App configuration delivering real webhooks to Shipit. They can craft an arbitrary raw JSON body where `repository.owner.login = "attacker-org"` (so the controller selects and verifies against the attacker's own known secret) while setting `repository.full_name = "victim-org/victim-repo"` and providing a `pull_request.head` pointing at attacker-controlled content. They compute the HMAC-SHA1 signature themselves using their own `webhook_secret` over this crafted body and POST it to `/webhooks` with `X-Github-Event: pull_request`. `verify_signature` passes (correct secret for `attacker-org`), and `ReopenedHandler` then unarchives/mutates the review stack belonging to `victim-org/victim-repo` — a repository the attacker never authenticated for.

Existing guards fail here because: `drop_unhandled_event` and `check_if_ping` don't inspect repository identity; `verify_signature` only binds the secret choice to `owner.login`, never to `full_name`; the `ExplicitParameters` schema in `ReopenedHandler` only validates presence/type of `full_name`, not its consistency with the authenticating owner; and `Repository.from_github_repo_name`/`ReviewStackAdapter` perform no authorization check tying the resolved record back to the org that signed the request.

This is only exploitable in genuinely multi-tenant configurations where `Shipit.github_organizations` returns more than one organization (each with separate `webhook_secret`s) and the attacker legitimately controls one of those tenants. In a single-org deployment (`github_default_organization` is `nil`, single `secrets.github` schema), there is only one `webhook_secret`, and an attacker with no valid GitHub App/webhook integration cannot produce any valid signature at all, since `verify_webhook_signature` requires a matching HMAC — this constrains but does not eliminate the vulnerability class in a multi-tenant setup.

### Impact Explanation
In a multi-tenant deployment, one onboarded/legitimate tenant can forge webhook payloads that mutate another tenant's `ReviewStack`/`Repository` state (`unarchive!`, and by the same pattern in sibling handlers such as `ClosedHandler`, `LabeledHandler`, `OpenedHandler`, `UnlabeledHandler`, `AssignedHandler`, `EditedHandler` — all of which share the identical `repository` resolution pattern via `from_github_repo_name(params.repository.full_name)`), since none of them re-verify that `full_name`'s owner matches the signing organization. This is a cross-tenant write consistent with the Critical category ("a payload for one repository mutating another's stack"). It is repeatable against any repository name present in the `Repository` table, for any tenant, from any attacker who is themselves an onboarded tenant of a multi-org Shipit instance.

### Likelihood Explanation
Requires: (1) Shipit configured with the multi-organization GitHub App schema (`secrets.github` keyed by org, each with a distinct `webhook_secret`), and (2) attacker legitimately controls at least one such tenant's `webhook_secret` (e.g., is a customer/org admin of a shared Shipit instance). In a single-org deployment this vector is not reachable because there is no separate secret an unprivileged attacker could know. Given the multi-tenant precondition, attacker cost is low: they only need to craft a JSON body and HMAC-sign it with their own known secret and POST to `/webhooks`; fully repeatable and scriptable.

### Recommendation
In `WebhooksController#verify_signature` (or in a shared handler concern), after successfully verifying the signature, assert that the `owner.login` used to select the `webhook_secret` matches the owner segment parsed from `params.repository.full_name` before dispatching to handlers; reject (422) on mismatch. Alternatively, have each handler (or `Handler` base class) re-derive/validate `repository.full_name`'s owner against the `X-Hub-Signature`-verified organization rather than trusting `full_name` on its own.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/pull_request/reopened_handler_test.rb (minitest, multi-org secrets fixture)
test "cross-tenant full_name spoof is not blocked before dispatch" do
  # Configure secrets.github with two orgs: attacker-org (secret: attacker_secret), victim-org (secret: victim_secret)
  # victim_repo belongs to victim-org and has a review_stack that is archived.
  victim_repo = shipit_repositories(:victim_repo) # owner: 'victim-org', name: 'victim-repo'
  victim_stack = victim_repo.review_stacks.create!(...) # archived

  payload = {
    action: 'reopened',
    number: 1,
    pull_request: {
      id: 1, number: 1, url: 'https://x', title: 't', state: 'open',
      additions: 0, deletions: 0,
      head: { sha: 'deadbeef', ref: 'attacker-branch' },
      user: { login: 'attacker' },
      assignees: [], labels: []
    },
    repository: { owner: { login: 'attacker-org' }, full_name: 'victim-org/victim-repo' },
    sender: { login: 'attacker' }
  }.to_json

  signature = 'sha1=' + OpenSSL::HMAC.hexdigest('sha1', 'attacker_secret', payload)

  request.headers['X-Github-Event'] = 'pull_request'
  request.headers['X-Hub-Signature'] = signature

  post :create, body: payload, as: :json

  # Assert both sides of the binding:
  assert_response :ok # signature verified against attacker-org's own secret
  victim_stack.reload
  assert_not victim_stack.archived?, "victim-org's stack must not be unarchived by attacker-org's signed payload"
  # If this assertion fails (stack is unarchived), the provenance binding
  # repository_owner(signing org) == owner(full_name) is broken.
end
```

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

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L41-45)
```ruby
          def process
            return unless respond_to_pull_request_reopened?

            stack.unarchive!
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L49-53)
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
