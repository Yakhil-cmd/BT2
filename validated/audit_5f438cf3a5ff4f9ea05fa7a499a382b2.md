Confirmed: `Handler#stacks` looks up the target `Repository` purely from `payload.dig('repository', 'full_name')` [1](#0-0) , and handlers like `PushHandler#process`, `StatusHandler#process`, `CheckSuiteHandler#process` act on that repository/commit data with no re-check against the organization used to verify the webhook signature [2](#0-1) [3](#0-2) [4](#0-3) .

### Title
Webhook signature is verified against an attacker-controlled organization while handlers act on an unrelated repository - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to check the HMAC signature against by reading `repository_owner` straight out of the **unverified** JSON payload, before any signature check has happened. The handlers that subsequently act on the payload identify the target repository by an entirely separate field, `repository.full_name`, that is never cross-checked against the organization whose secret validated the signature.

### Finding Description
`verify_signature` derives the organization used for HMAC verification from the request body itself:
```
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [5](#0-4) 
and uses it to fetch the corresponding `GitHubApp`/secret:
```
github_app = Shipit.github(organization: repository_owner)
verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
``` [6](#0-5) 

Shipit supports hosting multiple GitHub Apps/organizations side by side in one installation, each with its own `webhook_secret` in `secrets.yml` (see `github_organizations` / `github_app_config`) [7](#0-6) , and the test/dummy config demonstrates two independently-configured orgs, `OrgOne` and `OrgTwo`, each installed on the same Shipit instance [8](#0-7) .

Once the signature is accepted, the actual work is dispatched with the raw, unrestricted `params`:
```
Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }
``` [9](#0-8) 
and every handler picks its target purely from `payload.dig('repository', 'full_name')`:
```
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [1](#0-0) 

There is no assertion anywhere that `repository.owner.login` (used to pick the verifying secret) equals the owner portion of `repository.full_name` (used to pick the affected `Repository`/`Stack`). This breaks the equality: *organization that authenticated the request* == *repository that is written*. This is the same class of bug as the CCTP hook report — a value that gates/authorizes an operation (the before-hook boolean / the signing organization) is not the same value the operation actually acts on (the second `depositForBurn` call / the target repository), so a value that "passed the gate" for one purpose is silently reused to authorize a different, unchecked target.

### Impact Explanation
An attacker who administers (or otherwise knows the configured `webhook_secret` for) any one of the multiple GitHub organizations hosted on a shared Shipit instance can forge a signature that is valid for their own org, while setting `repository.full_name` in the JSON body to `victim-org/victim-repo`. Because `verify_signature` only checks that the signature matches *some* configured org's secret (chosen by attacker-controlled `repository.owner.login`), and the handlers act on the independently attacker-controlled `repository.full_name`, the forged webhook is accepted and processed as if it legitimately came from GitHub for the victim repository. This allows:
- Forged `push` events that trigger `stack.sync_github` on a victim's stack [2](#0-1) , potentially advancing the recorded HEAD or triggering pipeline sync for a repo the attacker does not control.
- Forged `status`/`check_suite` events that write commit statuses and trigger check-run refreshes against a victim's commits [3](#0-2) [4](#0-3) , which can be leveraged to satisfy CI-gating requirements (`ci.require`) that Shipit deploy gating relies on, ultimately enabling an unauthorized deploy of a victim's stack.

This is a cross-repository/cross-organization write and can escalate to an unauthorized deploy, matching the Critical impact bar ("cross-repository writes ... or an unauthorized deploy").

### Likelihood Explanation
This is only exploitable in the (documented, supported) multi-organization configuration where more than one GitHub App/organization with independently-managed `webhook_secret`s share a single Shipit instance [10](#0-9) . An attacker needs to know the secret for at least one hosted organization — plausible if they are an admin of one lower-trust tenant org on a shared Shipit deployment (a realistic multi-tenant scenario the engine explicitly supports), without needing any Shipit account, `ApiClient` token, or access to the victim organization's own secret.

### Recommendation
After computing `repository_owner` and verifying the signature, re-derive the organization from `repository.full_name` (or any other field the handlers will actually use) and require it to match `repository_owner` before dispatching to handlers; reject the webhook (422) on mismatch. Alternatively, scope handler repository lookups to only repositories belonging to the organization whose secret validated the request.

### Proof of Concept
1. Host Shipit configured with two orgs, `OrgOne` (attacker-controlled, secret known to attacker) and `OrgTwo` (victim, tracked repo `OrgTwo/victim-repo`) as in `test/dummy/config/secrets_double_github_app.yml` [8](#0-7) .
2. Attacker builds a JSON payload:
```json
{
  "repository": { "owner": { "login": "OrgOne" }, "full_name": "OrgTwo/victim-repo" },
  "ref": "refs/heads/master",
  "after": "<attacker chosen sha>"
}
```
3. Attacker computes `X-Hub-Signature: sha1=<hmac(OrgOne_webhook_secret, raw_body)>` and sends it as a `push` event to `/webhooks`.
4. `verify_signature` resolves `repository_owner` = `"OrgOne"`, fetches `OrgOne`'s app/secret, and the signature validates successfully [6](#0-5) .
5. `PushHandler` is invoked with the full payload and resolves the target repository from `repository.full_name` = `"OrgTwo/victim-repo"` [1](#0-0) , triggering `sync_github` on `OrgTwo`'s stack despite the request never being signed by `OrgTwo`.

### Citations

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** lib/shipit.rb (L190-200)
```ruby
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

**File:** test/dummy/config/secrets_double_github_app.yml (L1-41)
```yaml
  github:
    OrgOne:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
      # Randomly generated
      private_key: |
        -----BEGIN RSA PRIVATE KEY-----
        MIIEpAIBAAKCAQEA7iUQC2uUq/gtQg0gxtyaccuicYgmq1LUr1mOWbmwM1Cv63+S
        73qo8h87FX+YyclY5fZF6SMXIys02JOkImGgbnvEOLcHnImCYrWs03msOzEIO/pG
        M0YedAPtQ2MEiLIu4y8htosVxeqfEOPiq9kQgFxNKyETzjdIA9q1md8sofuJUmPv
        ibacW1PecuAMnn+P8qf0XIDp7uh6noB751KvhCaCNTAPtVE9NZ18OmNG9GOyX/pu
        pQHIrPgTpTG6KlAe3r6LWvemzwsMtuRGU+K+KhK9dFIlSE+v9rA32KScO8efOh6s
        Gu3rWorV4iDu14U62rzEfdzzc63YL94sUbZxbwIDAQABAoIBADLJ8r8MxZtbhYN1
        u0zOFZ45WL6v09dsBfITvnlCUeLPzYUDIzoxxcBFittN6C744x3ARS6wjimw+EdM
        TZALlCSb/sA9wMDQzt7wchhz9Zh2H5RzDu+2f54sjDh38KqancdT8PO2fAFGxX/b
        qicOVyeZB9gv6MJtJc20olBbuXAeBNfcDABF9oxF+0i+Ssg7B4VXiqgcjtGbr/Og
        qRll7AqyTArVx2xEcVfZxeZ4zGnigzcJq4te7yYpxzwk+RxblkPh54Yt4WxZ+8DI
        Rsn3r6ajlpwzpwvsJFU2Txq7xBTzGQMFmy/Pnjk83kP2cogxB2+tRyjITGqTwD8b
        gg9PFCkCgYEA+7u8A0l0Cz6p0SI6c7ftVePVRiIhpawWN7og/wEmI6zUjm/3rA+R
        hrhaVKuOD8QF/HdDsqTck5gjGAjTmJz6r33/cl1Tz+pr62znsrB4r0yMKvQbKN81
        WGaWOsi2+ZXqLNv5h5wpUF0MTKlXHeKnwP5kuEvGwVn6WURFCh6PhLMCgYEA8i5e
        JjulJVGyd5HuoY3xyO7E6DjidsqRnVRq+hYpORjnHvTmSwe4+tH4ha2p9Kv2Y6k3
        C1NYY/fSMQoYCCRaYyJleI+la/9tsZqAmtms4ZB8KhFmPHf9fW75i6G0xKWyZ8K+
        E2Ft/UaEiM282593cguV6+Kt5uExnyPxLLK4FlUCgYEAwRJ/JGI8/7bjFkTTYheq
        j5q75BufhOrU6471acAe2XPgXxLfefdC3Xodxh0CS3NESBvNL4Ikr4sbN37lk4Kq
        /th7iOKtuqUIeru/hZy2I3VpeDRbdGCmEJQ2GwYA2LKztg5Nd0Y9paaIHXAwIfrK
        QUqcQ4HTAk8ZpUeoUBeaaeMCgYANLmbjb9WiPVsYVPIHCwHA7PX8qbPxwT7BsGmO
        KQyfVfKmZa/vH4F67Vi4deZNMdrcO8aKMEQcVM2065a5QrlEsgeR00eupB1lUEJ1
        qylUsZeAdqf43JMIc7TTW77KATa/nQLZbTEeWus1wvTngztuEqFbUGAks9cOkVc8
        FpIcbQKBgQDVIL8gPLmn0f+4oLF8MBC+oxtKpz14X5iJ1saGFkzW5I+nIEskpS0S
        qtirnTCnJFGdCrFwctnxiuiCmyGwpBYdjIfHyvYAHnqAtMnESzCUyeSFZiquVW5W
        MvbMmDPoV27XOHU9kIq6NXtfrkpufiyo6/VEYWozXalxKLNuqLYfPQ==
        -----END RSA PRIVATE KEY-----
      oauth:
        id: Iv1.bf2c2c45b449bfd9
        secret: ef694cd6e45223075d78d138ef014049052665f1
        teams:
    OrgTwo:
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
