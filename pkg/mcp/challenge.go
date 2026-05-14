package mcp

// ChallengeHeader builds a WWW-Authenticate value pointing at the PRM URL.
// Use it in your 401 responses (or rely on pkg/rs.Middleware, which sets
// this automatically when ResourceMetadata is configured).
func ChallengeHeader(resourceMetadataURL string) string {
	return `Bearer realm="authlet", resource_metadata="` + resourceMetadataURL + `"`
}
