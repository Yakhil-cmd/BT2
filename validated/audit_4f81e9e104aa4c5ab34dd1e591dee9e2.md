### Title
Webhook signature verified against `repository.owner.login`'s organization while all event handlers act on the unrelated `repository.full_name` field, allowing cross-repository status/push forgery - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` picks the `GitHubApp` (and thus the HMAC secret) used to validate an incoming webhook based on `repository_owner`, a value read straight out of the attacker-controlled JSON body (`repository.owner.login`, or `organization.login` as fallback). Every webhook handler, however, resolves its actual target `Stack`/`Repository`/`Commit` using a *different* field of the same body: `repository.full_name`. Because the two fields are never cross-validated, anyone who legitimately controls a webhook secret for **any one** organization configured in the Shipit instance can forge a validly-signed payload that claims to be `push`/`status`/`check_suite` for a **completely unrelated** organization's repository, and have Shipit act on it.

### Finding Description
`verify_signature` derives the signing organization purely from the payload: [1](#0-0) [2](#0-1) 

`Shipit.github(organization:)` maps that attacker-supplied organization name to a config/secret via a simple downcased-key lookup: [3](#0-2) 

`verify_webhook_signature` only checks that the HMAC over the raw body matches *that org's* `webhook_secret`: [4](#0-3) 

If the attacker is themselves an administrator of one organization onboarded into this Shipit instance (a legitimate, unprivileged-w.r.t.-other-tenants position), they know that organization's `webhook_secret` and can compute a valid HMAC for **any** JSON body of their choosing. Since `repository_owner` (used only to pick the secret) and `repository.full_name` (used everywhere else to resolve the target) are independent, attacker-controlled fields in the same body, the attacker sets `repository.owner.login` to their own org (so `verify_signature` picks their own valid secret) while setting `repository.full_name` to `victim-org/victim-repo`.

Every default handler trusts `repository.full_name` to select the target, with no re-check against the org that authenticated the request: [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7) 

This is precisely the bug class from the reference report: the engine caches/acts on an unverified, self-declared value (there, the pool balance used for pricing; here, `repository.full_name` used for authorization) instead of re-deriving it from the value that was actually cryptographically bound (there, on-chain reserves; here, the org whose secret produced a valid signature). The equality that should hold — `organization that authenticated == organization owning the repository being written` — is broken because the org used to select the secret and the repository acted upon come from two independently-attacker-controlled JSON keys inside the same signed blob.

### Impact Explanation
- `StatusHandler` lets the attacker inject a fabricated GitHub commit status (`state`, `context`, `target_url`, `description`) onto **any** `Commit` row in the database, keyed only by `sha` — a value that is public for any GitHub repo. Shipit's merge queue / deploy safety logic relies on "blocking statuses" recorded this way; an attacker can therefore forge a passing status on a victim stack's commit to help satisfy the checks gating merge/deploy, without any access to the victim's repository or its GitHub App installation. This lines up with the "unauthorized deploy...or merge" Critical impact category.
- `PushHandler` triggers `stack.sync_github(expected_head_sha:)` for any non-archived victim `Stack` matching the forged branch/SHA, letting an outsider force a resync using an attacker-chosen `after` SHA.
- `CheckSuiteHandler` schedules `RefreshCheckRunsJob` against arbitrary victim commits.

### Likelihood Explanation
The only prerequisite is administering (or being handed webhook access to) **any one** organization/app installation configured in the target Shipit deployment — not the victim organization. Multi-tenant Shipit installations (the `github_app_config`/per-organization secrets path in `lib/shipit.rb`) are an explicitly supported and documented configuration, so this is a realistic deployment for larger installs, and requires no elevated Shipit credentials, no `ApiClient` token, and no access to the victim org's GitHub App.

### Recommendation
Bind the signature-verification organization to the same field the handlers actually use to resolve the target repository (`repository.full_name`'s owner), and reject the request if `repository.owner.login` (or the fallback `organization.login`) does not match the owner segment of `repository.full_name`. Alternatively, have handlers re-derive/re-validate the acting organization from the value that was used for signature selection rather than trusting `repository.full_name` independently.

### Proof of Concept
1. Attacker legitimately administers `org-attacker`, configured in this Shipit instance with its own `webhook_secret`.
2. Attacker crafts a `status` webhook JSON body:
```json
{
  "sha": "<victim commit sha, public on GitHub>",
  "state": "success",
  "context": "ci/required-check",
  "repository": { "owner": { "login": "org-attacker" }, "full_name": "victim-org/victim-repo" }
}
```
3. Attacker computes `X-Hub-Signature` using `org-attacker`'s known `webhook_secret` over the exact raw body and POSTs it to `/webhooks` with `X-Github-Event: status`.
4. `verify_signature` calls `Shipit.github(organization: "org-attacker")` and validates the HMAC successfully — request passes.
5. `StatusHandler#process` runs `Commit.where(sha: params.sha)` — matching the victim commit purely by SHA, with no relation to `org-attacker` — and records the forged `success` status against it, independent of which org's secret was actually used.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-17)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class PushHandler < Handler
        params do
          requires :ref
          requires :after
        end

        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-24)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class StatusHandler < Handler
        params do
          requires :sha, String
          requires :state, String
          accepts :description, String
          accepts :target_url, String
          accepts :context, String
          accepts :created_at, String

          accepts :branches, Array do
            requires :name, String
          end
        end

        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L6-17)
```ruby
      class CheckSuiteHandler < Handler
        params do
          requires :check_suite do
            requires :head_sha, String
            requires :head_branch, String
          end
        end
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
        end
```
