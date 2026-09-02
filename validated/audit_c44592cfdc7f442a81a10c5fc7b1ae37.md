Confirmed: `Repository.from_github_repo_name` parses `owner` directly from the `full_name` string [1](#0-0) , and `Repository#github_app` derives the org used for the actual GitHub API client strictly from `owner` [2](#0-1) , which is looked up from the database record, not from the payload's `owner.login` field.

### Title
Webhook signature verified against an attacker-chosen organization while sync operates on a different organization's stack, allowing forged unauthenticated pushes to spend the victim org's `GITHUB_TOKEN` - (File: app/controllers/shipit/webhooks_controller.rb, app/models/shipit/webhooks/handlers/handler.rb)

### Summary
`WebhooksController#verify_signature` selects which organization's `webhook_secret` verifies an incoming request using `params.dig('repository', 'owner', 'login')`, while every downstream handler resolves the target stack/repository using the independent `payload.dig('repository', 'full_name')` field of the same attacker-supplied JSON body. Since these two fields are never cross-checked, an attacker who controls the full body of an unauthenticated `POST /webhooks` request can pick any organization for signature verification while directing the sync/API-spend logic at a completely different, victim organization's stack.

### Finding Description
The broken binding, stated as an equality that the code implicitly assumes but never enforces:

`params.dig('repository','owner','login')` (org used to select `webhook_secret` for verification) **must equal** `owner` derived from `payload.dig('repository','full_name')` (org whose `GITHUB_TOKEN`/`Shipit.github(organization:)` client is later used to service the request).

Trace:
1. `WebhooksController#verify_signature` computes `repository_owner` from `params.dig('repository', 'owner', 'login')` and calls `Shipit.github(organization: repository_owner).verify_webhook_signature(...)` [3](#0-2) .
2. `Shipit.github(organization:)`, in a multi-org configuration (`github_default_organization` non-nil), uses the *explicitly passed* `organization` argument to fetch that org's specific config/secret via `github_app_config(organization)` [4](#0-3) . So the attacker fully controls which org's `webhook_secret` is used to verify their own forged signature, simply by writing whatever value they want into `repository.owner.login` in the JSON body they POST.
3. `verify_webhook_signature` returns `true` unconditionally if that org's `webhook_secret` happens to be unset/nil [5](#0-4) , which the shipped example configs explicitly show as an optional/nil value [6](#0-5) .
4. After the signature check passes, `WebhooksController#create` dispatches the *same raw JSON body* to handlers (e.g. `PushHandler`) [7](#0-6) . `Handler#stacks` resolves the target repository/stack using an entirely separate field: `payload.dig('repository', 'full_name')` [8](#0-7) .
5. `Repository.from_github_repo_name` splits that `full_name` into owner/name and looks up the DB record [1](#0-0) ; this repository's own `owner` column (not the payload's `owner.login`) determines which `Shipit.github(organization:)` client (and thus whose `GITHUB_TOKEN`) is used for all subsequent API calls, via `Repository#github_app` [2](#0-1) .
6. `PushHandler#process` calls `stack.sync_github(expected_head_sha:)` for every matching stack [9](#0-8) , which enqueues `GithubSyncJob` [10](#0-9) . That job calls `stack.github_commits`, ultimately using `stack.repository`'s org-scoped GitHub API client (`Repository#github_app` → `Shipit.github(organization: owner)`) — the **victim** org's credentials — to fetch commit data and persist it, potentially reaching `User.find_or_create_author_from_github_commit` → `find_or_create_from_github` for authorship resolution [11](#0-10) .

The attacker's exact request: an unauthenticated `POST /webhooks` with header `X-Github-Event: push`, body `{"ref": "refs/heads/<branch>", "after": "<sha>", "repository": {"owner": {"login": "<org-with-no-or-attacker-known-webhook_secret>"}, "full_name": "<victim-org>/<victim-repo>"}}`. No `X-Hub-Signature` value need correspond to the victim org's real secret at all — it only has to satisfy verification for whatever org name the attacker put in `owner.login`.

Existing guards fail because: `drop_unhandled_event` only checks event name presence; `verify_signature` checks a signature but against an org chosen by attacker-controlled data, not the org that will actually be acted upon; there is no model validation or handler-side check enforcing `repository.owner.login == full_name.split('/').first`.

### Impact Explanation
This is a genuine confused-deputy / authentication-bypass condition: an unauthenticated request is verified against one tenant's secret but drives an operation (a background sync job that spends another tenant's installation `GITHUB_TOKEN` and can write `Commit`/`User` records) against a different tenant's stack. It is repeatable against any repository whose full name the attacker can guess/know (repo names/owners are typically public), and is exploitable across every tenant in a multi-org Shipit deployment as long as the attacker can get verification to pass for at least one organization (either one with a nil `webhook_secret`, or one whose secret has otherwise leaked/been guessed — the code makes no distinction). This matches "exfiltration/misuse of victim org's `GITHUB_TOKEN`" / "a payload for one repository mutating another's stack, commit ... team" in the Critical bucket.

### Likelihood Explanation
Preconditions: the Shipit installation must be running in the multi-organization `github:` config mode (sub-keyed by org) as documented, and at least one configured org must have a `webhook_secret` that is nil/blank (a documented, apparently supported configuration) or otherwise known/guessable by the attacker. Given that, the attacker's cost is a single crafted HTTP POST with no authentication, no session, and no knowledge of the victim org's actual secret — fully repeatable and automatable. If every configured org has a strong, secret `webhook_secret`, the specific "nil secret" bypass is unavailable, but the underlying architectural flaw (verifying-org ≠ acting-org) remains present as a latent defect that would be triggered by any future org with a misconfigured/blank secret, or if any org's real secret is otherwise compromised.

### Recommendation
Cross-validate that the organization used to select the webhook verification secret is the same organization that owns the target `repository.full_name` before dispatching to handlers — e.g., derive `repository_owner` from `full_name.split('/').first` (or explicitly assert `full_name` starts with `owner.login` + `/`) rather than trusting two independently-controlled fields of the same untrusted payload. Additionally, disallow/require a non-blank `webhook_secret` for every configured organization in multi-org mode so that `verify_webhook_signature` can never trivially return `true`.

### Proof of Concept
Minitest plan (`test/controllers/webhooks_controller_test.rb`), no live GitHub:
```ruby
test "push webhook signed for org A cannot sync a stack belonging to org B" do
  # org "attacker-org" configured with webhook_secret: nil (or a secret known to the attacker)
  # org "victim-org" configured with a real webhook_secret unknown to the attacker
  victim_stack = shipit_stacks(:victim) # repository.owner == 'victim-org'

  forged_payload = {
    "ref" => "refs/heads/#{victim_stack.branch}",
    "after" => "deadbeef",
    "repository" => {
      "owner" => { "login" => "attacker-org" },     # used for signature verification
      "full_name" => victim_stack.repository.github_repo_name # "victim-org/victim-repo" - used for the actual sync
    }
  }.to_json

  request.headers['X-Github-Event'] = 'push'
  # No knowledge of victim-org's webhook_secret required, since attacker-org's secret is nil/attacker-known

  Shipit.expects(:github).with(organization: 'victim-org').never
  # or: assert victim org's client is never invoked without victim org's own secret verifying the request

  assert_no_enqueued_jobs(only: GithubSyncJob) do
    post :create, body: forged_payload, as: :json
  end
end
```
This test asserts that `Shipit.github(organization: 'victim-org')`/`GithubSyncJob` for the victim stack is never triggered by a request whose signature was verified against a different organization's secret. As traced above, the current code fails this assertion because `WebhooksController` and `Handler#stacks` read the verifying-org and the acting-org from two independent, attacker-controlled JSON fields with no consistency check between them.

### Citations

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** app/models/shipit/repository.rb (L98-102)
```ruby
    protected

    def github_app
      Shipit.github(organization: owner)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-61)
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** config/secrets.development.example.yml (L8-16)
```yaml
github:
  app_id:
  installation_id:
  webhook_secret: # nil
  private_key:
  oauth:
    id:
    secret:
    teams: # Optional
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** app/models/shipit/stack.rb (L612-614)
```ruby
    def sync_github(expected_head_sha: nil)
      GithubSyncJob.perform_later(stack_id: id, expected_head_sha:)
    end
```

**File:** app/models/shipit/user.rb (L34-48)
```ruby
    def self.find_or_create_author_from_github_commit(github_commit)
      if (match_info = github_commit.commit.message.match(/^#{MergeRequest::MERGE_REQUEST_FIELD}: ([\w\-.]+)$/))
        begin
          return find_or_create_by_login!(match_info[1])
        rescue Octokit::NotFound
          # Corner case where the merge-requested-by user cannot be found (renamed/deleted).
          # In this case we carry on and search for the commit author
        end
      end
      find_or_create_from_github(github_commit.author.presence || github_commit.commit.author.presence)
    end

    def self.find_or_create_from_github(github_user)
      find_from_github(github_user) || create_from_github(github_user)
    end
```
