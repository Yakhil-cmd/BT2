### Title
Webhook signature is verified against the organization named in `repository.owner.login`, but handlers act on the unrelated `repository.full_name` field, allowing cross-organization webhook forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to check the `X-Hub-Signature` against, based solely on `repository.owner.login` (or `organization.login`) read from the unauthenticated JSON body. Once that signature check passes, the *entire* raw payload — including a completely independent `repository.full_name` field — is handed to the event handlers, which use `repository.full_name` to look up the `Shipit::Repository`/`Stack` to act on. Nothing ties the organization whose secret validated the signature to the repository the handler actually mutates.

### Finding Description
`Shipit.github(organization: repository_owner)` is used to fetch the `GitHubApp` (and its `webhook_secret`) to verify the signature: [1](#0-0) , where `repository_owner` is derived directly from the untrusted request body: [2](#0-1) .

Each Shipit installation can be configured with multiple, independently-secreted GitHub App organizations, looked up by name via `Shipit.github_app_config` / `TOP_LEVEL_GH_KEYS`: [3](#0-2) .

After the signature check passes, `create` passes the *full, raw* parsed body to every matching handler for the event, without re-deriving or cross-checking the organization: [4](#0-3) .

Handlers, however, resolve the target `Repository`/`Stack` using a completely different field of the same payload — `repository.full_name` — via `Handler#repository_name` / `Repository.from_github_repo_name`: [5](#0-4)  and [6](#0-5) . The same pattern repeats in several concrete handlers (e.g. `PullRequest::OpenedHandler`, `PullRequest::EditedHandler`), which independently call `Shipit::Repository.from_github_repo_name(params.repository.full_name)`: [7](#0-6) [8](#0-7) .

This is the same class of bug described in the external report: a message/payload is trusted and acted upon (marking an order executed / mutating a stack's state) based on an implicit assumption that a field validated by one mechanism (the bounce/signature) also guarantees the correctness of a different, unguarded field (`approved balance` / `repository.full_name`) that is actually used for the consequential action. Here the binding that should hold — "organization that authenticated == repository that is written" — is never enforced: `repository_owner` (used to pick the HMAC secret) and `repository.full_name` (used to pick the repo/stack to mutate) are two unrelated, independently attacker-controlled JSON fields inside the same signed byte string.

Because Shipit is designed to host many organizations (see `github_organizations`, `github_app_config`) each with its own `webhook_secret`, an attacker who legitimately controls one onboarded organization/GitHub App knows that organization's `webhook_secret` and can therefore compute a valid `X-Hub-Signature` for any payload of their choosing. By setting `repository.owner.login` to their own (legitimately configured) org — so the signature check passes — while setting `repository.full_name` (and any other repository-identifying sub-payload consumed by a specific handler) to a victim organization/repo also hosted on the same Shipit instance, the attacker can deliver a forged, validly-signed webhook that handlers will process against the victim's `Repository`/`Stack`.

### Impact Explanation
Depending on which event/handler is targeted, this crosses a repository boundary the attacker does not control, satisfying the "cross-repository writes" Critical criterion: e.g. `membership` handlers create/delete `Team`/`Membership` records, `status`/`check_suite` handlers can flip `Commit` deployable status (`create_status_from_github!`) and trigger `RefreshCheckRunsJob`, and PR handlers (`opened`, `edited`, `labeled`) can create/update `ReviewStack`s and `PullRequest` records tied to the victim's repository — all without any credential belonging to the victim organization. This is an authentication-binding bypass: the org whose secret authenticated the request is not the org/repo whose state is mutated.

### Likelihood Explanation
Exploitability requires the attacker to control (or have configured) at least one legitimate organization/GitHub App entry on the shared Shipit instance — a realistic scenario for any Shipit deployment serving multiple orgs/teams, which is exactly the multi-org configuration `Shipit.github_app_config` is built to support. No privileged Shipit session, `ApiClient` token, or GitHub App private key for the *victim* org is needed; only knowledge of the attacker's own configured `webhook_secret`, which they inherently possess.

### Recommendation
- Derive the organization used for signature verification from the same repository identifier subsequently used for routing (e.g., verify using the owner parsed from `repository.full_name`, not a separately-read `repository.owner.login`/`organization.login`), and reject payloads where these fields disagree.
- After selecting the `GitHubApp`/organization for signature verification, enforce in `WebhooksController#create` (or in `Handler#repository_name`) that every repository referenced in the payload belongs to that same, signature-verified organization before any handler acts on it.
- Add regression tests asserting that a payload signed with organization A's secret is rejected when it references a repository owned by organization B.

### Proof of Concept
1. Shipit is configured with two orgs in `secrets.github`: `org-attacker` (attacker-controlled, webhook secret known to attacker) and `org-victim` (hosts a Stack the attacker does not control).
2. Attacker crafts a `membership` (or `pull_request`/`status`) webhook JSON body:
   ```json
   {
     "action": "added",
     "organization": { "login": "org-attacker" },
     "repository": { "full_name": "org-victim/victim-repo", "owner": { "login": "org-attacker" } },
     "team": { "id": 1, "name": "x", "slug": "x", "url": "https://example.com" },
     "member": { "login": "attacker-login" }
   }
   ```
3. Attacker computes `X-Hub-Signature: sha1=HMAC(org-attacker_webhook_secret, raw_body)` and POSTs to `/webhooks` with `X-Github-Event: membership`.
4. `verify_signature` resolves `repository_owner` = `"org-attacker"`, fetches `org-attacker`'s `GitHubApp`, and the signature validates successfully: [1](#0-0) .
5. `create` forwards the full payload to the `membership` handler, which acts against `org-victim`'s data because it (or downstream repository-lookup logic) resolves the target using `repository.full_name`/other victim-scoped fields rather than the verified `org-attacker` scope: [4](#0-3) .

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/edited_handler.rb (L63-65)
```ruby
          def repository
            Shipit::Repository.from_github_repo_name(params.repository.full_name) || Shipit::NullRepository.new
          end
```
