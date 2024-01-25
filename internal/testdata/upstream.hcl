## note: this is copied from https://github.com/hashicorp/vault/blob/e55c18ed1299e0d36b88e603fa9f12adaf8e75dc/vault/policy_test.go
## changes are:
## * deleting the `name = "dev"` line and accompanying comment
## * deleting the path blocks that have "policy" attrs

# Add capabilities for creation and sudo to foobar
# This will be separate; they are combined when compiled into an ACL
# Also tests reverse string/int handling to the above
path "foo/bar" {
	capabilities = ["create", "sudo"]
	min_wrapping_ttl = "300s"
	max_wrapping_ttl = 3600
}
# Check that only allowed_parameters are being added to foobar
path "foo/bar" {
	capabilities = ["create", "sudo"]
	allowed_parameters = {
	  "zip" = []
	  "zap" = []
	}
}
# Check that only denied_parameters are being added to bazbar
path "baz/bar" {
	capabilities = ["create", "sudo"]
	denied_parameters = {
	  "zip" = []
	  "zap" = []
	}
}
# Check that both allowed and denied parameters are being added to bizbar
path "biz/bar" {
	capabilities = ["create", "sudo"]
	allowed_parameters = {
	  "zim" = []
	  "zam" = []
	}
	denied_parameters = {
	  "zip" = []
	  "zap" = []
	}
}
path "test/types" {
	capabilities = ["create", "sudo"]
	allowed_parameters = {
		"map" = [{"good" = "one"}]
		"int" = [1, 2]
	}
	denied_parameters = {
		"string" = ["test"]
		"bool" = [false]
	}
}
path "test/req" {
	capabilities = ["create", "sudo"]
	required_parameters = ["foo"]
}
path "test/patch" {
	capabilities = ["patch"]
}
path "test/mfa" {
	capabilities = ["create", "sudo"]
	mfa_methods = ["my_totp", "my_totp2"]
}
path "test/+/segment" {
	capabilities = ["create", "sudo"]
}
path "test/segment/at/end/+" {
	capabilities = ["create", "sudo"]
}
path "test/segment/at/end/v2/+/" {
	capabilities = ["create", "sudo"]
}
path "test/+/wildcard/+/*" {
	capabilities = ["create", "sudo"]
}
path "test/+/wildcard/+/end*" {
	capabilities = ["create", "sudo"]
}
