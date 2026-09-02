### Title
Cross-organization webhook authentication bypass lets a `pull_request` payload from one GitHub org overwrite another org's `PullRequest` record - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`Shipit::WebhooksController#verify_signature` selects the webhook secret to validate a request using `repository_owner`, which is computed from `params.dig('repository','owner','login') || params.dig('organization','login')`, while `AssignedHandler#repository` resolves the actual target `Repository`/`Stack` using an entirely different, independently-controlled field, `params.repository.full_name`. Because `AssignedHandler`'s `ExplicitParameters` schema only requires `repository.full_name` and never requires or cross-checks `repository.owner.login`, an attacker who controls a repository under one GitHub organization configured on a multi-org Shipit instance can forge a `pull_request`/`assigned` webhook that authenticates as their own (or any weakly-configured) organization while writing into a victim `PullRequest` belonging to a completely different organization's stack.

### Finding Description
The broken invariant, stated as an equality that the code implicitly assumes but never enforces: `repository_owner` (used to pick the `GitHubApp`/`webhook_secret` for signature verification) should equal the organization that owns `params.repository.full_name` (used by the handler to locate the target `Repository`/`Stack`/`PullRequest`). In this codebase these are two independent, attacker-supplied values:

- Verifier selection: `Shipit::WebhooksController#repository_owner` [1](#0-0)  falls back to `params.dig('organization', 'login')` if `repository.owner.login` is absent from the JSON body, and `verify_signature` uses this value to pick which org's `GitHubApp` (and thus which `webhook_secret`) validates the HMAC signature [2](#0-1) .
- Target resolution: `AssignedHandler#repository` looks up the record purely from `params.repository.full_name` [3](#0-2) , and the handler's `ExplicitParameters` schema requires only `repository.full_name`, never `repository.owner.login` or any relation to `organization.login` [4](#0-3) .
- `Shipit.github(organization:)` genuinely picks a different `GitHubApp`/secret per organization only when the multi-org config schema is used (`github_default_organization` non-nil); in that mode `github_app_config(organization)` is looked up by the passed `organization` argument, i.e., the attacker-controlled `repository_owner` value [5](#0-4) . `GitHubApp#verify_webhook_signature` returns `true` unconditionally when that organization's `webhook_secret` is blank [6](#0-5) .

Exploit flow: On a Shipit instance configured for "Using Multiple GitHub Applications" (documented feature), the attacker owns/controls an org, "attacker-org", registered on the same Shipit instance (or knows of any configured org whose `webhook_secret` is unset). They send `POST /webhooks` with header `X-Github-Event: pull_request` and a JSON body where:
- `organization.login = "attacker-org"` (and `repository.owner.login` omitted, so `repository_owner` resolves to `"attacker-org"`),
- `repository.full_name = "victim-org/victim-repo"` (the real target, entirely different org),
- `action = "assigned"`, plus the other required `pull_request` fields.

`verify_signature` computes/validates using `attacker-org`'s secret (known to the attacker or absent), passes, and `AssignedHandler#process` then finds the `Shipit::PullRequest` belonging to `victim-org/victim-repo`'s stack by `number` and calls `pull_request.update(github_pull_request: params.pull_request)` [7](#0-6) , overwriting `title`, `state`, `additions`, `deletions`, `user`, `assignees`, `labels`, and `head` commit via `PullRequest#github_pull_request=` [8](#0-7) , using attacker-chosen values for a PR record the attacker never authenticated for.

None of the existing guards catch this: `drop_unhandled_event`/`check_if_ping` only gate on event type, not on the org/repo mismatch; the `ExplicitParameters` schema for `AssignedHandler` validates shape but never cross-validates `repository.full_name`'s owner against `repository_owner`/`organization.login`; and `verify_signature` never compares the org it authenticated against the org actually referenced by the payload's `repository.full_name`.

### Impact Explanation
An attacker who authenticates as (or exploits an unsecured) organization A can cause writes to `PullRequest` rows owned by an unrelated organization B's stack — this is a payload for one repository mutating another repository's/stack's records, matching the "Critical" category explicitly called out in the rules ("a payload for one repository mutating another's stack, commit, task or team"). This is repeatable against any `number` on any victim stack reachable via a guessed/known repository `full_name`, is not rate-limited, and requires no privileges on the victim repository/stack whatsoever — only that the Shipit instance uses (or has ever used) the multi-org GitHub App configuration and the attacker controls or knows of one weakly-secured org slot. The `blocking_statuses`/`blocked?` amplification claimed in the question (forcing deploy gating) is not directly demonstrated here: `AssignedHandler` mutates PR metadata (title, state, assignees, labels, head commit) via `github_pull_request=`, not `blocking_statuses`/commit-status records, so the specific "forced status gates deploys" mechanism in the question is unsubstantiated by this handler; the confirmed impact is the cross-tenant `PullRequest` record write itself.

### Likelihood Explanation
Exploitability is conditional on the target Shipit deployment using the documented multi-organization GitHub App configuration (`config/secrets.yml` keyed by org names) — in the common single-org configuration, `Shipit.github` ignores the passed `organization` argument entirely and always uses the single top-level secret, so the divergence is a no-op there [9](#0-8) . Given multi-org configuration, the attacker's cost is low: any GitHub user who owns a repository under one of the configured orgs (or who discovers an org slot with a blank `webhook_secret`) can compute a valid signature for that org and forge an arbitrary `pull_request.repository.full_name` pointing at any other configured org's repo/stack — fully repeatable and scriptable, with no interaction from the victim required.

### Recommendation
In `AssignedHandler` (and other webhook handlers that read `repository.full_name` independently), require `repository.owner.login` in the schema and assert it equals the `repository_owner` value that authenticated the request (pass it through as verified context, not re-derive it from the payload), or derive the target repository strictly from the same field used for signature verification. At minimum, `WebhooksController#verify_signature` should record which organization/owner authenticated the payload and every handler should refuse to act if `params.repository.full_name`'s owner segment does not match that authenticated organization.

### Proof of Concept
Minitest plan (no live GitHub):
1. Configure `Shipit.stubs(:secrets)` with two orgs: `attacker-org` (no `webhook_secret`, or a known one) and `victim-org` (with its own `webhook_secret`), mirroring `test/dummy/config/secrets_double_github_app.yml`.
2. Create a `victim-org/victim-repo` `Stack` with a `PullRequest` (`number: 42`, known `title`/`assignees`/`labels`).
3. POST to `/webhooks` with header `X-Github-Event: pull_request`, a valid (or absent-secret) signature for `attacker-org`, and body: `{"action":"assigned","number":42,"pull_request":{...attacker-chosen title/assignees/labels/head...},"repository":{"full_name":"victim-org/victim-repo"},"organization":{"login":"attacker-org"},"sender":{"login":"attacker"}}` (note: no `repository.owner.login`).
4. Assert response is `200 OK` (signature accepted for `attacker-org`).
5. Reload the `victim-org` `PullRequest` #42 and assert its `title`, `assignees`, `labels` now equal the attacker-supplied values — i.e., `pull_request.reload.title == "attacker chosen title"` — proving a payload authenticated for `attacker-org` mutated a `victim-org` record, violating the invariant "A `pull_request` event only affects the repository/stack whose secret authenticated it."

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

**File:** app/models/shipit/webhooks/handlers/pull_request/assigned_handler.rb (L33-39)
```ruby
            requires :repository do
              requires :full_name, String
            end
            requires :sender do
              requires :login, String
            end
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/assigned_handler.rb (L41-45)
```ruby
          def process
            return unless respond_to_assignee_change?

            pull_request.update(github_pull_request: params.pull_request) if pull_request.present?
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/assigned_handler.rb (L67-69)
```ruby
          def repository
            Shipit::Repository.from_github_repo_name(params.repository.full_name) || Shipit::NullRepository.new
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
