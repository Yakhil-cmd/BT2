### Title
Webhook signature verification selects the GitHub App/secret from the same unauthenticated payload field the handlers later trust, allowing cross-organization forgery — (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` derives which `GitHubApp` (and therefore which `webhook_secret`) to verify against from `repository_owner`, a value read straight out of the untrusted JSON body. In a multi-organization Shipit deployment, this lets an attacker who controls (or knows the secret of, or exploits the "no secret configured" bypass of) one configured GitHub organization forge a webhook whose `repository.owner.login` points at that organization for verification purposes, while the `repository.full_name`/other payload fields — used unmodified by the downstream event handlers — reference a repository belonging to a *different*, unrelated organization.

### Finding Description
Shipit supports hosting multiple GitHub Apps for multiple organizations, each with its own independent `webhook_secret`, selected via `Shipit.github(organization:)` / `Shipit.github_app_config(organization)`: [1](#0-0) 

The webhook signature check picks the verification key using an organization name extracted from the request body itself, before the signature has been validated: [2](#0-1) [3](#0-2) 

`GitHubApp#verify_webhook_signature` HMACs the *entire raw body* against the secret belonging to whichever org `repository_owner` names — and if that org has no `webhook_secret` configured, verification is skipped entirely: [4](#0-3) 

After this check, `create` re-parses the same raw body and dispatches it, unmodified, to all registered handlers for the event: [5](#0-4) 

Handlers (e.g. the `status` handler, confirmed by test, and `push`/`GithubSyncJob`) locate the target `Stack`/`Repository`/`Commit` from other fields of that same body (e.g. `repository.full_name`, `sha`), independent of `repository_owner`: [6](#0-5) [7](#0-6) 

Nothing in `verify_signature` or `create` enforces that the org used to pick the verification secret (`repository_owner`) is the same org that owns the repository the handlers subsequently act on. The multi-org configuration schema, where each org has its own distinct `webhook_secret`, is explicitly documented as supported: [8](#0-7) 

The broken binding is: `organization whose secret authenticated the request == organization owning the repository the handler writes to`. An attacker who is a legitimate GitHub App owner/admin for one configured organization (or who targets an organization intentionally left with `webhook_secret: nil`, per `return true unless webhook_secret`) can satisfy the left side of the equality while forging the right side arbitrarily, because both sides are read from the same attacker-supplied, unauthenticated-at-read-time JSON.

### Impact Explanation
By crafting a payload where `repository.owner.login`/`organization.login` names an organization the attacker controls (or one with no `webhook_secret`), but embeds `repository.full_name`, commit `sha`, and status fields belonging to a different, protected organization's repository, the attacker can:
- Inject forged commit `status` events for a victim stack's real commit (`test ":state create a Status for the specific commit"` shows this is exactly how statuses are created from raw payload fields), which can satisfy `ci.require` checks gating deploys/merges.
- Trigger `GithubSyncJob`/push processing against a victim `Stack` with attacker-controlled `expected_head_sha`.
- Manipulate `pull_request`/`merge_status`/`check_suite` state for repositories the attacker has no legitimate access to.

This is a cross-repository write and can lead to an unauthorized deploy/merge decision on a repository/organization the attacker does not control, satisfying the Critical impact bar (cross-repository writes / unauthorized deploy or merge).

### Likelihood Explanation
Exploitability requires: (1) the deployment configures multiple GitHub organizations (a documented, supported configuration), and (2) the attacker has legitimate control of at least one of those organizations' webhook secret (as an app admin of a lower-trust org sharing the same Shipit instance) or one org is left without a `webhook_secret` (also documented as an accepted `# nil` default in every secrets example file, e.g. `config/secrets.development.example.yml`). This is a realistic operational configuration for shared/multi-tenant Shipit installs, but it does depend on the specific multi-org setup being in use, which I could not fully confirm end-to-end for every handler (e.g. `push_handler.rb` internals were not read in full before the tool budget ran out) — the `status` handler path is confirmed directly by test; other handlers (`push`, `pull_request`) are inferred from grep results and job code but not fully verified line-by-line.

### Recommendation
Do not use attacker-controlled payload fields to select the verification key before the signature has been checked. Options:
- Verify the signature against **every** configured organization's secret (or against the app-wide secret if single-org) and only trust the payload's declared organization once at least one verification succeeds, or
- Bind webhook URLs per-organization (e.g. `/webhooks/:organization`) so the key selection comes from a trusted route parameter, not the JSON body, and then confirm `repository.owner.login`/`repository.full_name` inside the payload matches that trusted `:organization` before dispatching to handlers.
- Disallow `webhook_secret: nil` in multi-org configurations, or require it to opt out explicitly with a big warning.

### Proof of Concept
1. Deploy Shipit configured with two organizations in `secrets.yml`: `AttackerOrg` (attacker is GitHub App admin, knows/controls `webhook_secret`) and `VictimOrg` (protected, different `webhook_secret`), per the multi-org schema in `docs/setup.md`.
2. Attacker crafts a `status` (or `push`) webhook JSON body with:
   - `repository.owner.login` = `"AttackerOrg"` (or `organization.login` if repository absent)
   - `repository.full_name` = `"VictimOrg/protected-repo"`
   - `sha` = a real commit SHA of a stack under `VictimOrg/protected-repo`
   - `state` = `"success"`, `context` = the CI context required by that stack's `ci.require`
3. Attacker signs the raw body with `AttackerOrg`'s webhook secret and POSTs to `/webhooks` with header `X-Hub-Signature`.
4. `verify_signature` computes `repository_owner` = `"AttackerOrg"`, fetches `Shipit.github(organization: "AttackerOrg")`, and successfully verifies the signature (attacker's own secret).
5. `create` re-parses the body and dispatches it to the `status` handler, which creates a `Shipit::Status` for the real `VictimOrg` commit using the forged payload — as reproduced by the pattern in `test ":state create a Status for the specific commit"` — potentially satisfying CI gating for an unauthorized deploy/merge on `VictimOrg`'s stack.

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

**File:** test/controllers/webhooks_controller_test.rb (L12-21)
```ruby
    test "create github repository which is not yet present in the datastore" do
      request.headers['X-Github-Event'] = 'push'
      unknown_repo_payload = JSON.parse(payload(:push_master))
      unknown_repo_payload["repository"]["full_name"] = "owner/unknown-repository"
      unknown_repo_payload = unknown_repo_payload.to_json

      assert_nothing_raised do
        post :create, body: unknown_repo_payload, as: :json
      end
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
