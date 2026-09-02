### Title
Webhook signature verified against `repository.owner.login`'s org secret while handlers act on the unrelated `repository.full_name` field, enabling cross-organization commit-status/ref spoofing - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController` selects which GitHub organization's `webhook_secret` to verify the HMAC signature against using `repository.owner.login` (or `organization.login`), but the event handlers that actually mutate state look up the target `Stack`/`Repository`/`Commit` using a *different* field in the same JSON body: `repository.full_name`. In a multi-organization Shipit deployment these two fields are never cross-checked against each other, so a payload can be signed with one organization's legitimate webhook secret while acting on a repository belonging to a completely different, unrelated organization tracked by the same Shipit instance.

### Finding Description
`WebhooksController#verify_signature` computes the verifying org purely from attacker-controlled payload content: [1](#0-0) [2](#0-1) 

`Shipit.github(organization:)` resolves to a per-organization `GitHubApp` instance carrying that organization's own `webhook_secret`, as configured under the documented "Using Multiple Github Applications" setup: [3](#0-2) [4](#0-3) 

Once the HMAC check passes, `WebhooksController#create` dispatches the full parsed payload to handlers unmodified: [5](#0-4) 

Every handler resolves its target repository from `repository.full_name`, a field never covered by the org-selection logic used for signature verification: [6](#0-5) 

`StatusHandler` then writes a `Status` object directly from the payload's fields onto any `Commit` matching the given `sha`, with no correlation back to the verifying organization: [7](#0-6) 

`PushHandler` and `CheckSuiteHandler` behave the same way — they derive `stacks` from `repository.full_name` via `Handler#stacks`/`#repository_name`, then trigger `sync_github`/`schedule_refresh_check_runs!` against those stacks, regardless of which org's secret validated the request: [8](#0-7) [9](#0-8) 

The binding that is broken is: **organization whose webhook_secret authenticated the request** (`repository.owner.login` / `organization.login`) **≠ organization/repository actually written by the handler** (`repository.full_name`). Before the attack these are always equal for genuine GitHub-delivered webhooks (GitHub always sets both fields consistently for the repo the event actually occurred in). After the attack, an attacker who legitimately controls their own GitHub organization/App installation on the same Shipit instance (and therefore legitimately possesses that org's `webhook_secret`) can forge a payload where `repository.owner.login` is their own org (making the HMAC check pass) but `repository.full_name` points at an entirely different, unrelated tracked repository belonging to another organization.

### Impact Explanation
This breaks the deployment-trust boundary between organizations hosted on the same shared Shipit instance. `StatusHandler` allows the attacker to inject arbitrary commit statuses (`state`, `description`, `target_url`, `context`) onto commits of a repository they do not control, which can be used to satisfy or corrupt CI-gating checks that `Stack` deploy safety logic depends on — a path toward an unauthorized deploy of another organization's repository. `PushHandler` lets the attacker trigger `stack.sync_github` on another org's stacks with an attacker-chosen `expected_head_sha`. This qualifies as High severity per the rubric (escalation across the organization authorization boundary / unauthenticated write of stack/commit state that the attacker's own credentials should not reach), and depending on how commit statuses gate deploy eligibility could rise to an unauthorized deploy (Critical).

### Likelihood Explanation
Exploitability requires only that the Shipit instance be configured with the documented multi-organization GitHub App schema (explicitly supported and documented) and that the attacker legitimately administers at least one of the configured organizations (a routine, low-privilege scenario — e.g., an internal team with its own GitHub org onboarded to a shared Shipit deployment). No GitHub App private key, no Shipit session, and no privileged Shipit account is needed — only knowledge of one's own org's webhook secret, which the attacker legitimately possesses. The webhook endpoint is public (`/webhooks`, unauthenticated by design, protected only by the HMAC check).

### Recommendation
Bind organization selection for signature verification to the same field(s) the handlers use to identify the write target, and reject the request if they disagree. Concretely, after resolving `repository.full_name` (or `repository.owner.login`) to a `Repository`/`Stack` record, verify that the resolved repository's owning organization matches the organization whose secret produced a valid signature (`repository_owner`), and reject (422) on mismatch before invoking any handler.

### Proof of Concept
1. Configure Shipit with two organizations, `OrgA` and `OrgB`, each with its own GitHub App and `webhook_secret` (per `docs/setup.md`, "Using Multiple Github Applications").
2. Attacker legitimately administers `OrgA` and knows `OrgA`'s `webhook_secret`.
3. Attacker (or their GitHub App) POSTs to `/webhooks` a `status` event payload:
```json
{
  "sha": "<victim-commit-sha-in-OrgB>",
  "state": "success",
  "repository": { "full_name": "OrgB/victim-repo", "owner": { "login": "OrgA" } }
}
```
4. `X-Hub-Signature` is computed with `OrgA`'s webhook secret over the raw body.
5. `WebhooksController#verify_signature` resolves `repository_owner` = `"OrgA"`, fetches `OrgA`'s `GitHubApp`, and successfully verifies the signature (`app/controllers/shipit/webhooks_controller.rb:24-30`).
6. `StatusHandler#process` (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`) looks up `Commit.where(sha: params.sha)` — the victim commit in `OrgB/victim-repo` — and writes a forged `success` status, despite the attacker never having any relationship to `OrgB`.

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

**File:** docs/setup.md (L182-209)
```markdown
### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

```yml
production:
  github:
    somegithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
    someothergithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
```
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
        end
```
