### Title
Cross-organization webhook forgery via mismatched signature/authorization binding in `WebhooksController#verify_signature` - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
In a multi-GitHub-App Shipit deployment, `WebhooksController#verify_signature` selects which organization's `webhook_secret` to use for HMAC verification based on an **unauthenticated** payload field (`repository.owner.login` / `organization.login`), while the actual write target (the `Stack`/`Repository` acted upon) is resolved from a **different** payload field (`repository.full_name`) that is never cross-checked against the field used to pick the secret. This breaks the intended binding "organization that authenticated == repository that is written."

### Finding Description
`verify_signature` computes `repository_owner` straight from the untrusted JSON body and uses it to look up the `GitHubApp`/secret that will validate the signature: [1](#0-0) [2](#0-1) 

`Shipit.github(organization:)` looks up per-organization config (each org can have its own `webhook_secret`) via `github_app_config`: [3](#0-2) 

The signature is verified over the entire raw body using that selected secret: [4](#0-3) 

However, once the signature passes, the actual entity mutated is resolved from a **different** field of the same payload — `repository.full_name` — via `Handler#stacks`/`Repository.from_github_repo_name`, with no re-validation that it belongs to the same organization that supplied the verified secret: [5](#0-4) [6](#0-5) 

Because an attacker fully controls the JSON body (`repository.owner.login`, `organization.login`, and `repository.full_name` are independent, non-cross-validated keys in the same untrusted payload), a holder of a legitimate but weaker organization's webhook secret (e.g., an org they administer that is also configured in this same Shipit instance, per `docs/setup.md`'s "Using Multiple Github Applications" schema) can:
1. Set `repository.owner.login` (or `organization.login`) to their own org, `OrgA`, so `Shipit.github(organization: "OrgA")` is selected and its known `webhook_secret` is used for verification.
2. Sign the raw body with `OrgA`'s secret — the signature is valid.
3. Set `repository.full_name` to `"OrgB/target-repo"` — a repository belonging to a different, unrelated organization, `OrgB`, hosted on the same Shipit instance.
4. The `WebhooksController#create` action dispatches to handlers (`push_handler.rb`, `status_handler.rb`, etc.) which resolve the target `Stack` purely from `repository.full_name`, i.e. `OrgB`, and act on it — even though the cryptographic authentication was performed against `OrgA`.

This is analogous to the Cally bug class: a validated field (`tokenIdOrAmount`) that is checked is not the same field that determines impact, letting an attacker manipulate an uncontrolled/unchecked value to cause unintended state changes elsewhere — here, the "checked" organization (used for the HMAC) is decoupled from the "acted-upon" repository, which is never checked at all.

### Impact Explanation
The most damaging concrete handler is `StatusHandler`, which creates a GitHub commit status record for any commit whose `sha` matches, regardless of which repository it came from: [7](#0-6) 

Since Shipit gates deploy safety/CI checks on commit statuses, and `Commit.where(sha: params.sha)` is looked up globally (not scoped by the verified/forged `repository.full_name` at all in this handler), an attacker who only legitimately controls `OrgA`'s webhook secret can forge a `status` event that is authenticated as `OrgA` but reports a fabricated "success"/CI status for a commit belonging to `OrgB`'s stack, potentially satisfying deploy prerequisites and enabling an unauthorized deploy of `OrgB`'s code — meeting the "unauthorized deploy" Critical/High impact criterion. `PushHandler` similarly triggers `stack.sync_github` for any stack resolved via the forged `repository.full_name`, letting the attacker trigger sync/ref-tracking actions on a stack belonging to an org they never authenticated as.

### Likelihood Explanation
This requires: (a) the Shipit instance to be configured with the multi-organization GitHub App schema (documented and supported: `docs/setup.md`, `test/dummy/config/secrets_double_github_app.yml`), and (b) the attacker to possess a valid webhook secret for at least one of the configured organizations (e.g., they administer that org's GitHub App, a legitimate but lower-trust tenant). Given that, forging the payload requires no special access — just a raw HTTP POST to `/webhooks` with a correctly-signed body using their own known secret. No session, `ApiClient` token, or GitHub App private key is required — only knowledge of one org's `webhook_secret`, which is exactly the credential this endpoint is designed to accept as proof of "this webhook is from that org's repos," not "any repo."

### Recommendation
After signature verification succeeds, re-derive `repository_owner` from `repository.full_name` (or the `organization.login`) and assert that it matches the organization that was used to select the `webhook_secret`. Concretely, add a check in `WebhooksController#verify_signature` (or in `Handler#stacks`) such as: `head(422) unless repository_owner.casecmp?(payload.dig('repository', 'full_name')&.split('/')&.first)`, i.e. bind the verified organization to the repository actually acted upon, so a secret valid for `OrgA` can never authorize actions against `OrgB`'s stacks.

### Proof of Concept
1. Configure Shipit with two organizations, `OrgA` and `OrgB`, each with its own `webhook_secret` (per `docs/setup.md` multi-app schema), and a `Stack` backed by `Repository owner: "OrgB", name: "target-repo"`.
2. As an attacker who is an admin/owner of `OrgA`'s GitHub App (and thus knows `OrgA`'s `webhook_secret`), craft a `status` event payload:
```json
{
  "sha": "<sha-of-OrgB-target-repo-commit>",
  "state": "success",
  "context": "ci/forged",
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/target-repo" }
}
```
3. Compute `X-Hub-Signature: sha1=<hmac_sha1(OrgA_webhook_secret, body)>`.
4. `POST /webhooks` with `X-Github-Event: status` and the above signature.
5. `verify_signature` calls `Shipit.github(organization: "OrgA")` (from `repository.owner.login`), verifies successfully against `OrgA`'s secret, and the request proceeds.
6. `StatusHandler#process` looks up `Commit.where(sha: params.sha)` — matching the commit that actually lives under `OrgB/target-repo` — and calls `create_status_from_github!`, injecting a forged, attacker-authored CI status onto `OrgB`'s commit despite the attacker never having proven any relationship to `OrgB`.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
