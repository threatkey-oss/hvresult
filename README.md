# hvresult

**hvresult** is a small static analyzer and GitOps tool for Hashicorp Vault ACL policies. Give it a token, token accessor, or a path to a Vault role (like `/auth/gcp/role/example`) and it'll tell you what that can do - and importantly - what policies say that it's allowed to do it.

Like [gpresult](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/gpresult) for Group Policy objects, hvresult computes the Resultant Set of Policy (RSoP) for Hashicorp Vault ACLs.

See `[our blog post about hvresult]()` for more details.

# Usage and example output

As per usual with Go tools, you can install with `go install` or extract [a release binary](https://github.com/threatkey-oss/hvresult/releases/latest) to your `$PATH`.

```
go install github.com/threatkey-oss/hvresult@latest
```

## Use with ad-hoc analysis

RSoP for a particular auth principal can be emitted as either HCL or a Markdown table.

```sh
# as HCL, for those who work with it often
$ VAULT_TOKEN=$(vault print token) \
    hvresult auth/kerberos/groups/devs
```

```hcl
# generated by hvresult

path "aws/dev/roles/humans" {
  capabilities = [
    "read", # from: devs-aws
  ]
}

path "aws/dev/sts/humans" {
  capabilities = [
    "create", # from: dev-aws
    "update", # from: dev-aws
  ]
}

path "secret2/+/dev/oidc-apps" {
    "list", # from: dev-oidc-apps-ro, dev-oidc-apps-rw
}

path "secret2/+/dev/oidc-apps/*" {
    "create", # from: dev-oidc-apps-rw
    "read",   # from: dev-oidc-apps-ro
    "update", # from: dev-oidc-apps-rw
    "list",   # from: dev-oidc-apps-ro
}
```

```sh
# as a Markdown table for those who don't
$ VAULT_TOKEN=$(vault print token) \
 hvresult auth/kerberos/groups/devs \
 --format table
```

| Path                       | Change | Capability | Policy / Policies                  |
| -------------------------- | ------ | ---------- | ---------------------------------- |
| aws/dev/roles/humans       | ➕     | read       | devs-aws                           |
| aws/dev/sts/humans         | ➕     | create     | devs-aws                           |
|                            | ➕     | update     | devs-aws                           |
| secret2/+/dev/oidc-apps    | ➕     | list       | dev-oidc-apps-ro, dev-oidc-apps-rw |
| secret2/+/dev/oidc-apps/\* | ➕     | create     | dev-oidc-apps-rw                   |
|                            | ➕     | read       | dev-oidc-apps-ro                   |
|                            | ➕     | update     | dev-oidc-apps-rw                   |
|                            | ➕     | list       | dev-oidc-apps-ro                   |

## Use in GitOps

hvresult can be used to implement a GitOps flow that uses a git repository to manage policy and authentication.

To try it out or see what it'd look like, run `hvresult gitops download` to download a copy of your entire Vault authentication and ACL setup:

```sh
$ VAULT_TOKEN=$(vault print token) \
  hvresult gitops download -d ~/gitops/vault-policy
2:50PM WRN LIST path returned empty response, skipping listPath=auth/token/roles secret=null
2:50PM INF downloaded all auth principals count=0 mount=auth/token/
2:50PM INF downloaded all auth principals count=1 mount=auth/aws/
2:50PM INF downloaded all auth principals count=2 mount=auth/azure/
2:50PM INF downloaded all auth principals count=1 mount=auth/gcp/
2:50PM INF downloaded all policies count=277
$ tree ~/gitops/vault-policy
├── auth
│   ├── aws
│   │   └── role
│   │       └── just
│   ├── azure
│   │   └── role
│   │       ├── a-couple
│   │       └── of-example
│   ├── gcp
│   │   └── role
│   │       └── role-names
│   └── token
│       └── roles
└── sys
    └── policies
        └── acl
            [...]
            ├── default
            [...]
```

After doing so, you turn this directory into a GitOps repository for Vault permission change control.

The path to each file is where it's available in your Vault cluster. Authentication principals under `auth/` contain only token-relevant fields like `.token_policies`, while each of the policies under `sys/policies/acl` contain a copy of the HCL for each policy.

### Use in Pull Request Review

`hvresult` assists with merge/pull request review by illustrating changes both policy assignment and policy definition changes. Say that a PR contains the following change:

```sh
# here's what the changes are...
~/gitops/vault-policy $ git diff main
diff --git a/kubernetes/role/snowflake-dev b/kubernetes/role/snowflake-dev
index f38c070..2ab6961 100644
--- a/kubernetes/role/snowflake-dev
+++ b/kubernetes/role/snowflake-dev
@@ -1,6 +1,6 @@
 {
   "token_policies": [
     "log-ingestion-producer-dev",
-    "dev_snowflake_ro"
+    "dev_salesforce_rw"
   ]
 }
diff --git a/sys/policies/acl/devs b/sys/policies/acl/devs
index 3840b41..2e78965 100644
--- a/sys/policies/acl/devs
+++ b/sys/policies/acl/devs
@@ -32,3 +32,7 @@ path "unchanged/item" {
 path "unchanged/item" {
   capabilities = ["create", "update"]
 }
+
+path "oopsnewthing/+" {
+  capabilities = ["read"]
+}
# and here's what it means!
~/gitops/vault-policy $ go run ./main.go gitops diff > out.md
3:18PM INF detected changes to files count=1
3:18PM INF processing change path=auth/kubernetes/role/snowflake-dev
~/gitops/vault-policy $ cat out.md
3 changes to `auth/kubernetes/role/snowflake-dev`

| Path                    | Change | Capability | Policy / Policies |
| ----------------------- | ------ | ---------- | ----------------- |
| dev/secret/salesforce   | ➕      | create     | dev_salesforce_rw |
|                         | ➕      | read       | dev_salesforce_rw |
|                         | ➕      | update     | dev_salesforce_rw |
|                         | ➕      | delete     | dev_salesforce_rw |
| dev/secret/salesforce/+ | ➕      | create     | dev_salesforce_rw |
|                         | ➕      | read       | dev_salesforce_rw |
|                         | ➕      | update     | dev_salesforce_rw |
|                         | ➕      | delete     | dev_salesforce_rw |
| dev/secret/snowflake    | ➖      | read       | dev_snowflake_ro  |
| dev/secret/snowflake/+  | ➖      | read       | dev_snowflake_ro  |

1 effective change to `auth/kerberos/groups/developers`.

| Path           | Change | Capability | Policy / Policies |
| -------------- | ------ | ---------- | ----------------- |
| oopsnewthing/+ | ➕      | read       | devs              |

1 effective change to `auth/kerberos/groups/devtest`.

| Path           | Change | Capability | Policy / Policies |
| -------------- | ------ | ---------- | ----------------- |
| oopsnewthing/+ | ➕      | read       | devs              |
```

This output is formatted as [GitHub Flavored Markdown](https://github.github.com/gfm). Consider putting this in a pull request comment to illustrate changes!

### Actually making the changes to Vault

hvresult only addresses half of the GitOps problem; you'll still have to apply the changes. In practice this is usually effected by custom tooling, but only because the risk assessment of granting a CICD worker privileges over Vault policy and role definitions will vary widely.

Support for issuing PUT/PATCH requests is not currently implemented, but a PR to create a `hvresult gitops apply` command to do it would be appreciated...!
