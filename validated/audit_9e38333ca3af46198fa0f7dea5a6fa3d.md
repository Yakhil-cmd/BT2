### Title
Webhook signature is bound to the payload's `repository.owner.login`, not to the `repository.full_name` that handlers act on, allowing cross-organization webhook forgery on multi-tenant Shipit deployments - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/handler.rb`)

### Summary
`Shipit.github(organization:)` supports a multi-organization configuration keyed by org name in `secrets.github`, each with its own independent `webhook_secret` [1](#0-0) . The `WebhooksController#verify_signature` action selects **which** organization's secret to validate the HMAC signature against using an unauthenticated field taken straight out of the JSON body — `repository_owner`, derived from `params.dig('repository', 'owner', 'login')` — before the signature itself has been checked [2](#0-1) . Once the signature is accepted, event handlers resolve the actual target `Repository`/`Stack` using a **different** field of the same payload: `payload.dig('repository', 'full_name')` [3](#0-2) . Nothing enforces that `repository.full_name`'s owner segment matches the `repository.owner.login` that was used to pick and validate the signing secret.

### Finding Description
This is the same trust-binding break described in the external report (an action is authorized against one field, while a different, unchecked field determines what is actually acted upon):

- Binding that should hold: `verified_organization(repository.owner.login) == acted_on_repository_org(repository.full_name)`
- What the code actually enforces: only that the payload is signed with the secret belonging to `repository.owner.login`. It never re-checks that `repository.full_name` is owned by that same organization.

Concretely:
1. `WebhooksController#verify_signature` fetches `github_app = Shipit.github(organization: repository_owner)` and validates `X-Hub-Signature` against `github_app.verify_webhook_signature` [4](#0-3) .
2. `Shipit.github_app_config(organization)` looks up the secret purely by the lowercased org name found in `secrets.github`, with each org given its own independent `webhook_secret` [5](#0-4) .
3. After the request passes, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` is invoked with the entire raw payload, unmodified [6](#0-5) .
4. Every handler (`PushHandler`, `CommitStatusHandler`, `MergeStatusHandler`, etc.) resolves the target stacks via `Handler#stacks`, which calls `Repository.from_github_repo_name(repository_name)` where `repository_name` is `payload.dig('repository', 'full_name')` — a completely separate JSON key from the one used for the signature-org lookup [3](#0-2) .

Because the two fields are never cross-checked, an actor who legitimately administers one organization configured on this shared Shipit instance (and therefore knows/possesses that org's real `webhook_secret`, as any GitHub App owner would) can craft a webhook body where `repository.owner.login` names their own org (so the HMAC check passes) while `repository.full_name` names a completely unrelated, victim organization's repository configured on the same Shipit deployment. The forged, correctly-signed request is then routed to the victim's stacks.

### Impact Explanation
This breaks the intended per-organization isolation of a multi-tenant Shipit installation. An attacker who is authorized only for organization A can forge events that are processed against organization B's stacks, including:
- `push` events that force `sync_github` on a victim's stack with an attacker-chosen `expected_head_sha` [7](#0-6) .
- `status`/`commit_status` and `merge_status` events, which (per the controller test coverage) create `Status` records directly from payload fields such as `state`, `target_url`, `description`, and `context` for a target commit [8](#0-7) , without re-validating those values against the real GitHub API.

Since `shipit.yml`'s `ci.require`/`ci.blocking` gates deploys purely on locally-stored `Status` rows for a commit [9](#0-8) , an attacker able to inject forged, cross-organization status events could mark a victim's commit as passing required CI checks it never actually passed, clearing the way for an unauthorized deploy/merge on infrastructure they do not control — satisfying the "unauthorized deploy, rollback, or merge" impact bar.

### Likelihood Explanation
Exploitation requires:
- The Shipit instance to be configured for **multiple organizations** (a documented, supported configuration path via `secrets.github` keyed by org name — not a misconfiguration of the engine) [1](#0-0) .
- The attacker to be a legitimate GitHub App owner/admin for at least one of those configured organizations (so they know that org's real `webhook_secret`) — no compromise of the victim organization, no Shipit session, and no `ApiClient` token are needed.

Given that, forging the cross-org payload is trivial: it only requires setting two independent JSON fields differently and signing with a secret the attacker legitimately possesses.

### Recommendation
In `WebhooksController#verify_signature` / `Handler`, cross-validate that the organization used to select and verify the webhook secret (`repository.owner.login`) matches the organization portion of `repository.full_name` before dispatching to handlers, rejecting (422) any payload where they diverge. Alternatively, derive the target repository/stack lookup from the same verified organization context rather than trusting an independent, unauthenticated payload field.

### Proof of Concept
1. Configure Shipit with two organizations in `secrets.github`: `org-a` (attacker-controlled, secret known to attacker) and `org-b` (victim, unrelated secret) [5](#0-4) .
2. Attacker crafts a `status` (or `push`) webhook JSON body:
   ```json
   {
     "repository": { "owner": { "login": "org-a" }, "full_name": "org-b/victim-repo" },
     "sha": "<victim commit sha>",
     "state": "success",
     "context": "ci/required-check",
     "branches": [{"name": "main"}]
   }
   ```
3. Attacker signs the raw body with `org-a`'s real `webhook_secret` and sets `X-Hub-Signature` accordingly, then sends it to `POST /webhooks`.
4. `verify_signature` resolves `Shipit.github(organization: 'org-a')` and validates the signature successfully [4](#0-3) .
5. The corresponding handler resolves the stack via `Repository.from_github_repo_name('org-b/victim-repo')` [3](#0-2)  and creates/updates a `Status` for the victim's commit, potentially satisfying a required CI check the attacker never actually ran.

### Citations

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

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

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

**File:** test/controllers/webhooks_controller_test.rb (L42-59)
```ruby
    test ":state create a Status for the specific commit" do
      request.headers['X-Github-Event'] = 'status'

      commit = shipit_commits(:first)

      body = JSON.parse(payload(:status_master)).merge(repository_params).to_json
      assert_difference 'commit.statuses.count', 1 do
        post :create, body:, as: :json
      end

      status = commit.statuses.last
      status_payload = JSON.parse(payload(:status_master))
      assert_equal status_payload['target_url'], status.target_url
      assert_equal status_payload['state'], status.state
      assert_equal status_payload['description'], status.description
      assert_equal status_payload['context'], status.context
      assert_equal status_payload['created_at'], status.created_at.iso8601
    end
```

**File:** README.md (L444-480)
```markdown
<h3 id="ci">CI</h3>

**<code>ci.require</code>** contains an array of the [statuses context](https://docs.github.com/en/rest/reference/commits#commit-statuses) you want Shipit to disallow deploys if any of them is missing on the commit being deployed.

For example:
```yml
ci:
  require:
    - ci/circleci
```

**<code>ci.hide</code>** contains an array of the [statuses context](https://docs.github.com/en/rest/reference/commits#commit-statuses) you want Shipit to ignore.

For example:
```yml
ci:
  hide:
    - ci/circleci
```

**<code>ci.allow_failures</code>** contains an array of the [statuses context](https://docs.github.com/en/rest/reference/commits#commit-statuses) you want to be visible but not to required for deploy.

For example:
```yml
ci:
  allow_failures:
    - ci/circleci
```

**<code>ci.blocking</code>** contains an array of the [statuses context](https://docs.github.com/en/rest/reference/commits#commit-statuses) you want to disallow deploys if any of them is missing or failing on any of the commits being deployed.

For example:
```yml
ci:
  blocking:
    - soc/compliance
```
```
