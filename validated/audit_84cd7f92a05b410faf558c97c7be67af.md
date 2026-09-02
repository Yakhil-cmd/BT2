### Title
Cross-organization webhook signature confusion allows attacker-signed payload to overwrite a victim repository's `PullRequest` record - ([File: app/models/shipit/webhooks/handlers/pull_request/assigned_handler.rb])

### Summary
`WebhooksController#verify_signature` derives the organization used to select the HMAC secret from `params.dig('repository', 'owner', 'login')`, while `AssignedHandler#repository` resolves the actual `Repository`/`Stack`/`PullRequest` to mutate from the independent field `params.repository.full_name`. Because nothing enforces that these two fields refer to the same organization, an attacker who controls a repository configured in Shipit (with their own `webhook_secret`) can sign a payload with `repository.owner.login = "attacker-org"` (passes signature check against attacker's own secret) while setting `repository.full_name = "victim-org/prod-repo"` and an arbitrary `number`, causing the handler to update a victim's `Shipit::PullRequest#github_pull_request` (including `head.sha`) with attacker-chosen content.

### Finding Description
The broken binding: the question implies `org whose secret verified the payload == org owning the PullRequest row updated`. Tracing the code:

- `WebhooksController#verify_signature` computes `repository_owner` as `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` and calls `Shipit.github(organization: repository_owner).verify_webhook_signature(...)`. [1](#0-0) [2](#0-1) 
- `Shipit::Webhooks::Handlers::PullRequest::AssignedHandler#repository` instead resolves the repo via `Shipit::Repository.from_github_repo_name(params.repository.full_name)`, a completely separate JSON field from `repository.owner.login`. [3](#0-2) 
- `pull_request` is then looked up joined to that resolved `repository.id`, and `.update(github_pull_request: params.pull_request)` is called on it unconditionally if found. [4](#0-3) 

The `AssignedHandler`'s `ExplicitParameters` schema only `requires :repository { requires :full_name, String }` — it never requires or validates `repository.owner.login`, and nothing cross-checks it against `full_name`. [5](#0-4) 

`Shipit.github(organization:)` selects a distinct `GitHubApp` (and therefore a distinct `webhook_secret`) per organization key from the multi-org secrets config. [6](#0-5) [7](#0-6) 

Exploit flow: attacker owns (or configures) a Shipit-registered organization `attacker-org` with a known `webhook_secret`. They POST to `/webhooks` with `X-Github-Event: pull_request` and body:
```json
{
  "action": "assigned",
  "number": <victim_pr_number>,
  "pull_request": { ... "head": {"sha": "<attacker-sha>", "ref": "..."} ... },
  "repository": { "owner": {"login": "attacker-org"}, "full_name": "victim-org/prod-repo" },
  "sender": {"login": "attacker"}
}
```
signed with `attacker-org`'s webhook secret. `verify_signature` computes `repository_owner = "attacker-org"`, fetches `Shipit.github(organization: "attacker-org")`, and the HMAC verifies successfully because the attacker legitimately owns that secret. The handler then resolves `repository` via `full_name = "victim-org/prod-repo"`, finds the victim's `Repository`, joins to find the victim `PullRequest` by `number`, and overwrites `github_pull_request` with the attacker-supplied JSON — including a forged `head.sha`.

Existing guards do not stop this: `verify_signature` only checks that *some* known organization's secret matches the raw body — it never checks that the resolved organization matches the repository actually referenced inside the payload used by the handler. `drop_unhandled_event` and the `ExplicitParameters` schema only validate shape/presence, not cross-field consistency. There is no model validation preventing a `PullRequest.update` write across organizations, since `Repository.from_github_repo_name` matches on `owner/name` parsed from attacker-supplied `full_name`, independent of `repository.owner.login`.

### Impact Explanation
The attacker can overwrite a victim organization's `Shipit::PullRequest#github_pull_request` JSON blob — including `head.sha`/`head.ref`/`title`/labels/assignees — for any `PullRequest` row whose `number` they can guess/enumerate, without ever holding the victim's webhook secret, Shipit session, or API token. If downstream deploy/review logic trusts `github_pull_request['head']['sha']` as the reviewed/deployed commit (common pattern in review-stack workflows), this is a cross-tenant integrity break that can influence what commit is considered "reviewed" or eligible for merge/deploy for a completely unrelated repository. This is repeatable against arbitrary victim repositories/PR numbers as long as the attacker controls one legitimately configured Shipit organization. This matches the Critical category "a payload for one repository mutating another's stack, commit, task."

### Likelihood Explanation
Preconditions: Shipit must be configured with the multi-org secrets schema (`github_app_config(organization)` keyed by org) and the attacker must control at least one such registered organization with a real webhook secret (a normal, low-privilege setup for any org onboarded to a shared Shipit instance). The victim `PullRequest` row must already exist (created by a legitimate prior PR event) and its `number` must be known/guessed — PR numbers are small sequential integers, easily enumerable. No GitHub App private key, victim webhook secret, or Shipit session is needed. This is a low-cost, fully repeatable attack requiring only the ability to send a signed HTTP POST from any organization present in the multi-org config.

### Recommendation
In `WebhooksController#verify_signature`, and/or in each handler's `repository` resolution, ensure the organization used to verify the HMAC signature is the same organization embedded in `repository.full_name` used to resolve the `Repository` record (e.g., verify `params.dig('repository','owner','login')&.downcase == params.dig('repository','full_name').to_s.split('/').first`, or better, derive `repository_owner` directly from `full_name` everywhere and reject payloads where `owner.login` disagrees with the owner segment of `full_name`).

### Proof of Concept
Add a minitest to `test/models/shipit/webhooks/handlers/pull_request/assigned_handler_test.rb` (or a controller test) demonstrating:

1. Arrange: create `victim_repo` (owner: `"victim-org"`, name: `"prod-repo"`) and `victim_pull_request` (`number: 2`, `github_pull_request: {"head" => {"sha" => "original-sha"}}`) joined via stack/repository.
2. Configure two orgs in `Shipit.secrets.github`: `attacker-org` with `webhook_secret: "attacker-secret"`, and `victim-org` with a different secret unknown to the attacker.
3. Build a payload where `repository.owner.login = "attacker-org"` and `repository.full_name = "victim-org/prod-repo"`, `number: 2`, `pull_request.head.sha = "attacker-sha"`.
4. Compute `X-Hub-Signature` using `attacker-org`'s secret (`"attacker-secret"`) over the raw JSON body.
5. `POST :create` with that body/signature/header `X-Github-Event: pull_request`.
6. Assert response is `:ok` (signature accepted) and:
   ```ruby
   assert_equal "attacker-sha", victim_pull_request.reload.github_pull_request["head"]["sha"]
   ```
   proving `victim_pull_request.github_pull_request['head']['sha']` changed from `"original-sha"` to `"attacker-sha"` using only `attacker-org`'s secret — with no access to `victim-org`'s secret.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/assigned_handler.rb (L33-35)
```ruby
            requires :repository do
              requires :full_name, String
            end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/assigned_handler.rb (L41-65)
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
```

**File:** app/models/shipit/webhooks/handlers/pull_request/assigned_handler.rb (L67-69)
```ruby
          def repository
            Shipit::Repository.from_github_repo_name(params.repository.full_name) || Shipit::NullRepository.new
          end
```

**File:** lib/shipit.rb (L170-181)
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
```

**File:** lib/shipit/github_app.rb (L44-51)
```ruby
    def initialize(organization, config)
      super()
      @mutex = Mutex.new
      @organization = organization
      @config = (config || {}).with_indifferent_access
      @domain = @config[:domain] || DOMAIN
      @webhook_secret = @config[:webhook_secret].presence
      @bot_login = @config[:bot_login]
```
