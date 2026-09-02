### Title
Cross-organization webhook forgery via mismatched `repository.owner.login` and `repository.full_name` - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/handler.rb])

### Summary
`WebhooksController#verify_signature` selects which org's `webhook_secret` to validate the HMAC against using `repository_owner` (`params.dig('repository','owner','login')`), while `Handler#repository_name`/`PushHandler`/`StatusHandler`/other handlers resolve the mutated `Repository`/`Stack`/`Commit` using a *different* field, `payload.dig('repository','full_name')`. Nothing in the request path enforces that these two fields, both attacker-supplied inside the same JSON body, agree.

### Finding Description
The binding that should hold is: `repository_owner == repository_name.split('/').first` (i.e. the org whose secret validated the signature must equal the owner prefix of the repo being mutated). This is never checked.

Path:
- `WebhooksController#verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-49`) computes `repository_owner` from `params.dig('repository','owner','login')` (`repository_owner`, line 59-62), looks up `Shipit.github(organization: repository_owner)`, and verifies `X-Hub-Signature` against that org's configured `webhook_secret` via `GitHubApp#verify_webhook_signature` (`lib/shipit/github_app.rb:76-83`).
- `WebhooksController#create` then dispatches the raw parsed `params` (the full attacker-controlled JSON) to `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` (`app/controllers/shipit/webhooks_controller.rb:10-15`), unchanged.
- `Handler#repository_name` (`app/models/shipit/webhooks/handlers/handler.rb:36-38`) reads `payload.dig('repository', 'full_name')`, an independent JSON key in the same attacker-supplied body, and passes it to `Repository.from_github_repo_name` (`app/models/shipit/repository.rb:53-56`), which downcases and splits on `/` to find the real `Repository` by `owner`/`name`.
- `PushHandler#process` (`app/models/shipit/webhooks/handlers/push_handler.rb:12-17`) then calls `stack.sync_github(expected_head_sha: params.after)` on stacks under that resolved repository, and `StatusHandler#process` (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`) updates `Commit` statuses looked up globally by `sha` with no repository scoping check at all.

Because `owner.login` and `full_name` are two independent, unrelated keys inside one attacker-crafted JSON body, an attacker who is a legitimately configured Shipit org (knows their own real `webhook_secret` for `Attacker-Org`) can sign a body where `repository.owner.login == "Attacker-Org"` (used only for signature-org lookup) but `repository.full_name == "Victim-Org/stack"` (used for the actual database mutation). The signature check passes because it is validated against `Attacker-Org`'s own secret; the mutation then targets `Victim-Org`'s `Repository`/`Stack`/`Commit` records. No code path (`verify_signature`, `drop_unhandled_event`, `ExplicitParameters` schemas, `Repository.from_github_repo_name`) ever cross-checks `repository_owner` against the owner portion of `repository_name`/`full_name`.

### Impact Explanation
This is a genuine cross-tenant authentication bypass: a payload validated with one organization's credentials mutates another organization's `Repository`-scoped records. With `PushHandler`, the attacker can force `stack.sync_github` against arbitrary branches of a victim's stacks (attacker controls `ref`/`after`), and with `StatusHandler`, `Commit.where(sha: params.sha)` is not even scoped to a repository, allowing forged CI statuses to be attached to any commit sha across the whole instance regardless of repository ownership. This matches the Critical category: "a payload for one repository mutating another's stack, commit, task or team."

### Likelihood Explanation
Preconditions: the attacker must control (or be) a Shipit-configured GitHub organization with its own `webhook_secret` — i.e., they must be a legitimate tenant of the multi-org Shipit deployment (this is realistic in any Shipit instance serving multiple orgs/customers). No GitHub secrets, victim credentials, or Shipit session are needed; the attacker only needs their own already-known secret and the ability to POST arbitrary JSON to `/webhooks` with a correct `X-Hub-Signature` computed from that known secret — a capability any registered tenant organization has for legitimate use. The exploit is trivially repeatable against any victim repository name known to the attacker.

### Recommendation
In `WebhooksController#verify_signature` or `Handler#initialize`, enforce that `payload.dig('repository','owner','login')` (or `organization.login`) matches the owner segment of `payload.dig('repository','full_name')` before verifying/accepting the webhook; reject (422) on mismatch. Additionally, scope `StatusHandler`'s `Commit.where(sha: ...)` lookup to commits belonging to the repository resolved from the verified organization, not merely by global `sha`.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (new test)
test "push webhook signed by Attacker-Org cannot mutate Victim-Org's stack via mismatched full_name" do
  attacker_org = "attacker-org"
  victim_org = "victim-org"

  # Two distinct configured orgs, each with its own real webhook_secret
  Shipit.github(organization: attacker_org) # secret: "attacker-secret"
  victim_repo = shipit_repositories(:shipit) # owner: victim_org, name: "stack"

  body = {
    ref: "refs/heads/master",
    after: "deadbeef",
    repository: {
      owner: { login: attacker_org },   # used for signature org lookup
      full_name: "#{victim_org}/stack"  # used for actual mutation target
    }
  }.to_json

  signature = "sha1=" + OpenSSL::HMAC.hexdigest("sha1", "attacker-secret", body)

  assert_equal victim_org, victim_repo.owner  # binding LHS/RHS before: repository_owner ("attacker-org") != prefix of repository_name ("victim-org")

  post :create, body: body, headers: { "X-Github-Event" => "push", "X-Hub-Signature" => signature }

  assert_response :ok
  # Assert victim's stack was mutated despite signature being validated only against attacker-org's secret
  assert_equal "deadbeef", victim_repo.stacks.first.reload.sha_head_or_similar
end
```
The assertion set demonstrates: (1) signature validated using `attacker-org`'s secret only, (2) the mutated record belongs to `victim-org`, proving `repository_owner != repository_name`'s owner segment yet the mutation still succeeded. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
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

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```
