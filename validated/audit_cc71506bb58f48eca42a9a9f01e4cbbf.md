Confirmed: `Repository#github_app` (and therefore `Stack#github_app`/`github_api`) is derived from `owner` — the repository's own owner column, not from the webhook's `repository_owner` — so `GithubSyncJob` will fetch commits using the *victim* org's own configured GitHub App credentials, not the attacker's. This makes the forged-webhook cross-org trigger fully effective: the attacker only needs to pass signature verification (using their own org's `webhook_secret`), and the engine will act on the victim's `Stack`/`Repository` using the victim org's own GitHub App/token.

### Title
Webhook signature verification keys on `repository.owner.login` while event handlers act on the unrelated `repository.full_name` field, allowing cross-organization forged webhooks - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App / `webhook_secret` to validate an inbound webhook against using `repository_owner`, taken from `params.dig('repository', 'owner', 'login')` (or `organization.login`). Once the signature check passes, every event `Handler` (via `Shipit::Webhooks::Handlers::Handler#repository_name`) instead looks up which `Repository`/`Stack` to act on using a *different* JSON field in the very same payload: `repository.full_name`. Nothing ties these two fields together, so an attacker who legitimately administers one Shipit-connected GitHub organization (and thus knows/controls that org's `webhook_secret`) can forge a webhook whose `repository.owner.login` is their own org (to pass signature verification) but whose `repository.full_name` names a completely different, victim organization's repository configured in the same Shipit instance.

### Finding Description
- `WebhooksController#verify_signature` picks the app/secret via `repository_owner`: [1](#0-0) , and `repository_owner` is read from the payload itself: [2](#0-1) .
- `verify_webhook_signature` only verifies the HMAC of the raw body against whatever secret was selected for that `repository_owner`: [3](#0-2) . It never checks that any other field of the payload (like `repository.full_name`) actually belongs to that organization.
- Every webhook `Handler` looks up the `Repository`/`Stack` to act on using `repository.full_name`, a sibling field never cross-checked against `repository.owner.login`: [4](#0-3) .
- `PushHandler` uses that lookup to trigger `stack.sync_github` on any matching, non-archived stack: [5](#0-4) .
- Pull-request handlers do the same to find/create or archive `ReviewStack`s, e.g. `OpenedHandler#repository`/`#process` provisions a new review stack: [6](#0-5) , and `ClosedHandler#process` archives (deprovisions) one: [7](#0-6) .
- Multi-organization support is a documented, first-class configuration: each top-level key under `github` in `secrets.yml` is a distinct organization with its own `webhook_secret`, and `Shipit.github(organization:)` resolves the app/secret purely from that key: [8](#0-7) , documented at [9](#0-8) .
- Critically, once a `Stack`/`Repository` is targeted this way, all subsequent GitHub API calls (`github_commits`, `github_api`, provisioning) are made using the **victim** organization's own GitHub App credentials, because `Repository#github_app` is derived from the repository's stored `owner` column, not from the webhook's `repository_owner`: [10](#0-9) , and `Stack#github_app` mirrors this: [11](#0-10) .

Binding broken: `organization authenticated by webhook signature` (`repository.owner.login`) ≠ `repository/stack actually written to` (`repository.full_name`). The signature only proves "this body was sent by someone who knows org A's secret" — it proves nothing about which repository the handlers should trust inside that same body.

### Impact Explanation
An attacker who is a legitimate admin/member of any GitHub organization that has installed the Shipit GitHub App (and thus who knows that org's own `webhook_secret`, which they are entitled to know for their own org) can POST a forged webhook directly to `/webhooks` with:
- `repository.owner.login` (or `organization.login`) = their own org, so `verify_signature` picks their own known secret and the HMAC passes,
- `repository.full_name` = `<victim_org>/<victim_repo>`, a totally unrelated organization's repository that also has Stacks configured in the same Shipit deployment.

This lets the attacker trigger `GithubSyncJob` / `sync_github` and pull-request driven provisioning (`ReviewStack` creation, archival, label-driven behavior) on the victim's stacks, using the victim's own GitHub App credentials for the resulting API calls — an unauthorized cross-repository/cross-organization action against a stack the attacker has no legitimate access to. This matches the Critical bucket "cross-repository writes, or an unauthorized deploy, rollback or merge."

### Likelihood Explanation
This requires only that the attacker be an authenticated admin of *some* other GitHub organization that shares the same Shipit deployment (a common real-world setup per the documented multi-org configuration) — no Shipit session, `ApiClient` token, or GitHub App private key is needed. Forging an arbitrary JSON body and computing its own HMAC with a secret they legitimately possess is trivial.

### Recommendation
Cross-validate that `repository.full_name`'s owner segment matches the `repository_owner` (or `organization.login`) used to select the webhook secret, rejecting (422) any payload where they diverge, before dispatching to handlers.

### Proof of Concept
1. Configure Shipit with two organizations in `secrets.yml`, `orgA` (attacker-administered) and `orgB` (victim), each with its own `webhook_secret`, and a `Stack` for `orgB/victim-repo`.
2. Attacker crafts a `push` (or `pull_request`) JSON payload with `repository.owner.login = "orgA"` and `repository.full_name = "orgB/victim-repo"`, `after`/`ref` set as desired.
3. Attacker computes `X-Hub-Signature: sha1=<hmac_sha1(orgA_webhook_secret, body)>` and POSTs it to `/webhooks` with `X-Github-Event: push`.
4. `verify_signature` resolves `repository_owner` = `"orgA"`, verifies successfully against `orgA`'s secret.
5. `PushHandler#stacks` resolves `Repository.from_github_repo_name("orgB/victim-repo")` and enqueues `GithubSyncJob`/`sync_github` for `orgB`'s stack, using `orgB`'s own GitHub App token for the resulting API calls — despite the attacker having no relationship to `orgB` whatsoever.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-53)
```ruby
          def process
            return unless respond_to_pull_request_opened?

            Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks).find_or_create!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
```

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L41-53)
```ruby
          def process
            return unless respond_to_pull_request_closed?

            review_stack.archive!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
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

**File:** app/models/shipit/repository.rb (L98-103)
```ruby
    protected

    def github_app
      Shipit.github(organization: owner)
    end
  end
```

**File:** app/models/shipit/stack.rb (L434-440)
```ruby
    def github_api
      github_app.api
    end

    def github_app
      Shipit.github(organization: repository.owner)
    end
```
