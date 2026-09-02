### Title
Signature verification keys off `repository.owner.login` while webhook handlers act on `repository.full_name` from the same unverified payload, allowing cross-repository status/sync forgery - (File: app/controllers/shipit/webhooks_controller.rb, app/models/shipit/webhooks/handlers/handler.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/org config (and thus which `webhook_secret`) to validate the HMAC signature against using `repository_owner`, derived from `params.dig('repository', 'owner', 'login')` in the raw, attacker-suppliable JSON body. [1](#0-0) [2](#0-1)  Once the signature check passes, the actual event handlers (`Shipit::Webhooks::Handlers::Handler`) determine which repository/stack to act on using a *different* field of the same body: `payload.dig('repository', 'full_name')`. [3](#0-2)  There is no check that `repository.full_name`'s owner segment matches `repository.owner.login`.

### Finding Description
Shipit supports multiple GitHub organizations, each with its own `webhook_secret`, keyed in `config/secrets.yml`. [4](#0-3)  `Shipit.github(organization:)` looks up the app/secret config purely by the organization name given to it, and `GithubApp#verify_webhook_signature` does a straightforward HMAC compare against `webhook_secret`. [5](#0-4) 

The binding that should hold is: *the organization whose secret validated the signature* == *the repository/organization the payload is allowed to act on*. In `WebhooksController`, the organization used for verification is read from the payload's `repository.owner.login` (or fallback `organization.login`), i.e. attacker-controlled data in the very body being authenticated. [2](#0-1)  Meanwhile, `PushHandler`, `StatusHandler`, `CheckSuiteHandler`, and other handlers resolve `stacks`/repository scope via `Repository.from_github_repo_name(payload.dig('repository','full_name'))`. [3](#0-2) [6](#0-5) 

Because a Shipit operator that supports several orgs (as documented) will have secrets for each of them, an attacker who controls one legitimate, low-privilege GitHub App installation (e.g. their own org, onboarded to the same Shipit instance) knows that org's `webhook_secret`. They can craft a raw POST body where `repository.owner.login` = their own org (to select and correctly HMAC-sign with the secret they know) while `repository.full_name` = `"victim-org/victim-repo"`. `verify_signature` succeeds because it validates the body against the attacker's own known secret, yet the handler layer then acts on the victim repository/stack, entirely bypassing GitHub's own guarantee that only GitHub (holding the real per-installation secret for `victim-org`) could produce a signed event about that repo.

`StatusHandler` is a particularly severe instance of this pattern because it doesn't even scope by repository at all — it matches by SHA globally: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }`. [7](#0-6)  An attacker who knows any real commit SHA in the victim's repository (SHAs are public on GitHub) can forge a `status` webhook — signed with their own org's secret — that flips that commit's CI status to `success` in Shipit.

### Impact Explanation
`Commit#deployable?` depends directly on cached CI status: `!locked? && (stack.ignore_ci? || (success? && !blocked?))`. [8](#0-7)  A forged `success` status on a victim commit that never actually passed CI makes that commit `deployable?` in Shipit's eyes, letting anyone with ordinary Shipit deploy permission — or continuous deployment — trigger deployment/merge of code that never passed the required CI gate (`ci.require`/`ci.blocking` checks, `DeploysController#create`'s `require_ci` check use `commit.deployable?`). [9](#0-8)  This constitutes an unauthorized-deploy vector via cross-repository/cross-organization write (falsified deployability state) crossing an authentication boundary (a different org's secret was used to authorize an action on the victim's repository) — matching the "Critical: unauthorized deploy" and "cross-repository writes" categories.

### Likelihood Explanation
Requires the attacker to control at least one legitimate GitHub App installation registered with the same Shipit instance (i.e., knowledge of one valid `webhook_secret` among potentially several configured orgs) and to know a target commit SHA in the victim repository (public on GitHub). No repository write access, GITHUB_TOKEN, or Shipit session/API token is needed — only the ability to send a raw HTTP POST to the public `/webhooks` endpoint with a self-signed payload. This is realistic in any multi-tenant Shipit deployment supporting several orgs, as explicitly documented as a supported configuration. [4](#0-3) 

### Recommendation
Bind signature verification to the same identity used for authorization: after `verify_webhook_signature` succeeds for organization `O`, require that `repository.full_name`'s owner segment (or `repository.owner.login`) actually equals `O`, and reject the payload otherwise. `Handler#repository_name`/`stacks` resolution should be constrained to repositories belonging to the organization that successfully validated the signature, not solely to attacker-supplied `full_name`. Additionally, `StatusHandler` should scope `Commit` lookups by the verified repository, not by bare SHA across the whole installation.

### Proof of Concept
1. Shipit instance configured with two orgs in `secrets.yml`: `victim-org` (real installation, secret unknown to attacker) and `attacker-org` (attacker's own installation, whose `webhook_secret` the attacker knows because they created that GitHub App).
2. Attacker finds a real commit SHA `abcd123...` in `victim-org/victim-repo` (public on GitHub) that has never passed CI in Shipit.
3. Attacker builds a JSON body:
```json
{
  "sha": "abcd123...",
  "state": "success",
  "context": "ci/circleci",
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" }
}
```
4. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(attacker-org secret, body)>` and POSTs to `/webhooks` with `X-Github-Event: status`.
5. `verify_signature` looks up `Shipit.github(organization: "attacker-org")` (from `repository.owner.login`) and validates successfully against the attacker's own secret. [1](#0-0) 
6. `StatusHandler#process` runs `Commit.where(sha: params.sha)` globally and sets a `success` status on the victim's commit, regardless of `repository.full_name`. [7](#0-6) 
7. The victim commit is now `deployable?` in Shipit, enabling deploy/merge without real CI having passed.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** docs/setup.md (L181-209)
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/controllers/shipit/api/deploys_controller.rb (L19-22)
```ruby
      def create
        commit = stack.commits.by_sha(params.sha) || param_error!(:sha, 'Unknown revision')
        param_error!(:force, "Can't deploy a locked stack") if !params.force && stack.locked?
        param_error!(:require_ci, "Commit is not deployable") if params.require_ci && !commit.deployable?
```
