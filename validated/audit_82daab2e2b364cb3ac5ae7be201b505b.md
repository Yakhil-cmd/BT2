### Title
Cross-tenant record mutation via mismatched `repository.owner.login` (signature-checked org) vs `repository.full_name` (target repo) in webhook body - (File: app/controllers/shipit/webhooks_controller.rb, app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb)

### Summary
`Shipit::WebhooksController#verify_signature` selects the GitHub App config (and thus the HMAC secret) using `repository_owner`, which is read from `params.dig('repository','owner','login')` [1](#0-0) , while `LabelCapturingHandler` (and the other PR handlers) resolve the target `Repository`/`Stack` independently from `params.repository.full_name` [2](#0-1) . If a Shipit deployment configures multiple GitHub organizations and one of them has no `webhook_secret`, `GitHubApp#verify_webhook_signature` returns `true` unconditionally for that org [3](#0-2) . Nothing enforces that `repository.owner.login` and the owner segment of `repository.full_name` refer to the same organization, so an attacker can pass verification "as" the no-secret org while the payload's `repository.full_name` targets a stack owned by a different (secret-protected) org.

### Finding Description
The broken binding is: *the organization whose `webhook_secret` verified the request* MUST equal *the organization owning the `Repository`/`Stack`/`PullRequest` the handler mutates*. In this codebase these are two independently-read fields of the same attacker-controlled JSON body:

- Verification org: `Shipit::WebhooksController#repository_owner` → `params.dig('repository','owner','login')` → `Shipit.github(organization: repository_owner)` → `github_app.verify_webhook_signature(...)` [4](#0-3) .
- Mutation target org: `LabelCapturingHandler#repository` → `Shipit::Repository.from_github_repo_name(params.repository.full_name)` [2](#0-1) , then `review_stack.stack` and `pull_request.update!(labels: ...)` [5](#0-4) .

`GitHubApp#verify_webhook_signature` short-circuits to `true` when `@webhook_secret` is blank [3](#0-2) , and multi-org configuration is a first-class, supported feature (`Shipit.github_organizations`, `Shipit.github_app_config`) [6](#0-5) . There is no code anywhere in `verify_signature` or in `LabelCapturingHandler` that cross-checks `repository.owner.login` against the owner segment of `repository.full_name`.

Exploit flow: attacker sends `POST /webhooks` with `X-Github-Event: pull_request`, body `{"action":"opened", "repository": {"owner": {"login": "noSecretOrg"}, "full_name": "victim-org/victim-repo"}, "pull_request": {..., "labels":[{"name":"MALICIOUS"}], ...}, ...}`. `verify_signature` resolves `Shipit.github(organization: "noSecretOrg")`, whose config has a blank `webhook_secret`, so `verify_webhook_signature` returns `true` regardless of the (even absent) `X-Hub-Signature`. The request passes through to `Shipit::Webhooks.for_event('pull_request')`, and `LabelCapturingHandler#process` looks up the repository/stack by `victim-org/victim-repo` (not `noSecretOrg`) and calls `pull_request.update!(labels: [...])`, mutating a PR record belonging to `victim-org`, whose own webhook_secret was never checked.

Existing guards do not stop this: `ExplicitParameters` only validates field shapes/types, not cross-field organizational consistency [7](#0-6) ; `drop_unhandled_event` only checks event type, not ownership; there's no `force_github_authentication`/`require_permission!` on this unauthenticated endpoint.

### Impact Explanation
The attacker can write labels onto an arbitrary PR record belonging to `Repository`/`Stack` for any organization configured in Shipit, as long as at least one *other* configured organization lacks a `webhook_secret`. Those forged labels are later uppercased into `ReviewStack#env`, which can influence environment variables surfaced to deploy/CI commands for the victim's review stack. This is a cross-repository/cross-tenant state manipulation matching the "Critical: a payload for one repository mutating another's stack/commit/task" category. Repeatable per request against any repository whose `full_name` is known/guessable, at no cost to the attacker.

### Likelihood Explanation
Requires: (1) the Shipit deployment uses multi-org GitHub App configuration (`Shipit.github_organizations` with more than one org), and (2) at least one configured org omits `webhook_secret`. This is a plausible but non-default operator misconfiguration — attacker cost is a single unauthenticated HTTP POST; no secrets, sessions, or team membership are needed. Feasibility depends entirely on operator config; it is not universally exploitable against every Shipit install, only ones with this specific multi-org/no-secret combination.

### Recommendation
In `Shipit::WebhooksController#verify_signature`, after resolving `github_app`, also verify that the organization derived from `params.dig('repository','full_name')`'s owner segment (or `params.dig('organization','login')`) matches `repository_owner` used for the secret lookup, rejecting (422) on mismatch. Additionally, consider disallowing blank `webhook_secret` for any configured organization in multi-org mode, since it effectively disables signature verification for that org and, transitively, for any payload claiming to belong to it.

### Proof of Concept
minitest (ActionDispatch::IntegrationTest), no live GitHub:
1. Configure `Rails.application.credentials.github` with two orgs: `no_secret_org` (no `webhook_secret`) and `victim_org` (with a `webhook_secret`).
2. Create `victim_org`'s `Repository`/`Stack`/`PullRequest` fixtures (e.g. `victim-org/victim-repo`, with an existing `Shipit::PullRequest` record, initial `labels: []`).
3. Build a `pull_request` `opened` JSON payload with `repository.owner.login = "no_secret_org"`, `repository.full_name = "victim-org/victim-repo"`, `pull_request.labels = [{name: "PWNED"}]`, and matching `head.sha`/`ref` to the victim's review stack.
4. `post "/webhooks", params: body, headers: { "X-Github-Event" => "pull_request", "X-Hub-Signature" => "sha1=deadbeef" }`.
5. Assert response is `200 OK` (not `422`), and assert `victim_pull_request.reload.labels == ["PWNED"]`, proving a payload verified under `no_secret_org`'s (absent) secret mutated a `victim_org`-owned record whose own `webhook_secret` was never checked.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L8-39)
```ruby
          params do
            requires :action, String
            requires :number, Integer
            requires :pull_request do
              requires :id, Integer
              requires :number, Integer
              requires :url, String
              requires :title, String
              requires :state, String
              requires :additions, Integer
              requires :deletions, Integer
              requires :head do
                requires :sha, String
                requires :ref, String
              end
              requires :user do
                requires :login, String
              end
              requires :assignees, Array do
                requires :login, String
              end
              requires :labels, Array do
                requires :name, String
              end
            end
            requires :repository do
              requires :full_name, String
            end
            requires :sender do
              requires :login, String
            end
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L98-102)
```ruby
          def capture_labels
            return unless pull_request = stack.pull_request

            pull_request.update!(labels: params.pull_request.labels.map(&:name))
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L110-113)
```ruby
          def repository
            @repository ||=
              Shipit::Repository
              .from_github_repo_name(params.repository.full_name) || NullRepository.new
```

**File:** lib/shipit/github_app.rb (L76-77)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret
```

**File:** lib/shipit.rb (L190-200)
```ruby
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
