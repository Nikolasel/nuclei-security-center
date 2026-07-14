package backend

import "testing"

// With an explicit access key, static V4 credentials are used verbatim — the
// local-dev / keyed-store path.
func TestResolveCredentialsStatic(t *testing.T) {
	creds := resolveCredentials(ObjectStoreConfig{AccessKey: "AKID", SecretKey: "SECRET"})
	v, err := creds.Get()
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if v.AccessKeyID != "AKID" || v.SecretAccessKey != "SECRET" {
		t.Fatalf("static creds = %q/%q, want AKID/SECRET", v.AccessKeyID, v.SecretAccessKey)
	}
}

// With no access key, the ambient chain is used; here it resolves from the
// environment (the EnvAWS provider), standing in for the instance-metadata IAM
// role path that isn't reachable in a unit test.
func TestResolveCredentialsAmbientFromEnv(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "ENVAKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "ENVSECRET")

	creds := resolveCredentials(ObjectStoreConfig{})
	v, err := creds.Get()
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if v.AccessKeyID != "ENVAKID" || v.SecretAccessKey != "ENVSECRET" {
		t.Fatalf("ambient creds = %q/%q, want ENVAKID/ENVSECRET", v.AccessKeyID, v.SecretAccessKey)
	}
}
