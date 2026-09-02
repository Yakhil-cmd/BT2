### Title
Global (repository-unscoped) status writes let a webhook signed by one GitHub organization forge CI status on commits belonging to a completely different tracked repository - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`WebhooksController#verify_signature` selects the HMAC secret to validate an inbound webhook based on the *organization* named in the payload (`repository.owner.login` / `organization.login`), then hands the entire parsed payload to whichever handler matches `X-Github-Event`. For the `status` event, `StatusHandler#process` never re-checks that the commit it is about to update actually belongs to a repository owned by that same organization — it looks the commit up **globally, by SHA, across every stack in the installation**. This breaks the equality "organization whose secret authenticated the request == repository whose data is written."

### Finding Description
`WebhooksController#verify_signature` derives the signing organization purely from attacker-controlled payload fields and looks up the matching `GitHubApp`/secret for verification: [1](#0-0) 

`repository_owner` is read straight from the JSON body: [2](#0-1) 

The base `Handler` class provides a `stacks`/`repository_name` helper that scopes lookups to the repository named in the payload: [3](#0-2) 

`CheckSuiteHandler` correctly uses this scoping (`stacks.where(branch: ...)`): [4](#0-3) 

But `StatusHandler` does not use `stacks`/`repository_name` at all — it queries `Commit` directly by `sha`, with no repository/organization filter whatsoever: [5](#0-4) 

Because Shipit supports multi-organization GitHub App configuration (`Shipit.github(organization:)` looks up per-organization secrets in `github_app_config`), an entity that legitimately owns/administers **any** organization configured in Shipit's `secrets.github` multi-org map can compute a valid `X-Hub-Signature` for that organization's webhook secret. That signature is only proof that "the payload was sent by someone with organization A's webhook secret" — it says nothing about which repository's commits the payload is allowed to affect. `StatusHandler` then trusts the `sha`/`state` fields inside that payload to write a status onto **any** commit row in the database that happens to share that SHA, regardless of which stack/repository it belongs to.

Root cause equality that is broken:
`organization whose webhook_secret verified the signature` **≠** `repository/stack whose Commit row StatusHandler mutates` (StatusHandler skips the `stacks`/`repository_name` scoping present in `Handler`/`CheckSuiteHandler`).

### Impact Explanation
Commit SHAs are not secrets — they are visible on GitHub for any repository the attacker can read (public repos, or private repos where the attacker has any read access, e.g. via a shared org). If Shipit is configured for multiple GitHub organizations (a supported and documented configuration, `secrets.github` keyed by org), an attacker who controls one configured organization's GitHub App/webhook secret can forge a `status` webhook naming a commit SHA that exists in a victim stack tracked under a different organization, and mark it `success` with an arbitrary `context`/`target_url`. Downstream, commit status/state feeds directly into deploy safety gates (`Commit#deployable?`/`require_ci` checks in `Api::DeploysController#create`), so a forged "success" status can help satisfy CI requirements and contribute to an unauthorized deploy of a commit that never actually passed CI in the target repository. This lands in the "unauthorized deploy" impact category.

### Likelihood Explanation
This requires the deployment to be configured with more than one GitHub organization/app (a supported, documented multi-org feature), and requires the attacker to control one of those organizations' webhook secret (e.g., because they administer that org's GitHub App) plus knowledge of a target commit's SHA (public information for any repo they can view). No API token, session, or repository write access to the *victim* repository is required — only ability to sign a webhook for a *different, unrelated* organization tracked by the same Shipit instance. This is a realistic misconfiguration-adjacent scenario for shared/hosted Shipit deployments serving multiple orgs.

### Recommendation
In `StatusHandler#process`, scope the commit lookup the same way `CheckSuiteHandler` and other handlers do — via `stacks` (derived from `payload.dig('repository', 'full_name')`) — instead of a bare `Commit.where(sha: params.sha)`:
```ruby
def process
  stacks.each do |stack|
    stack.commits.where(sha: params.sha).each do |commit|
      commit.create_status_from_github!(params)
    end
  end
end
```
This ensures the repository asserted in the signed payload (and validated indirectly via the org-specific webhook secret) is the same repository whose commit rows get mutated.

### Proof of Concept
1. Configure Shipit with two GitHub organizations, `attacker-org` and `victim-org`, each with its own GitHub App/webhook secret (per `secrets.github` multi-org schema in `lib/shipit.rb#github_app_config`).
2. Attacker controls `attacker-org`'s GitHub App and therefore knows its `webhook_secret`.
3. Attacker looks up (via GitHub's public API/UI) the SHA of a commit in `victim-org/some-repo` that is tracked as a Shipit stack.
4. Attacker crafts a `status` event payload:
   ```json
   {
     "sha": "<victim commit sha>",
     "state": "success",
     "context": "ci/forced",
     "repository": { "owner": { "login": "attacker-org" } }
   }
   ```
5. Attacker computes `X-Hub-Signature: sha1=HMAC(attacker-org_webhook_secret, body)` and POSTs to `/webhooks` with `X-Github-Event: status`.
6. `WebhooksController#verify_signature` resolves `Shipit.github(organization: 'attacker-org')` and successfully verifies the signature (it's the attacker's own valid secret).
7. `StatusHandler#process` runs `Commit.where(sha: params.sha)` — since this is unscoped, it matches the commit belonging to `victim-org/some-repo` and writes a fabricated `success` status to it, despite the request never being signed by `victim-org`'s webhook secret.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
