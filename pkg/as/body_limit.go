package as

import (
	"errors"
	"net/http"
)

// maxBodyBytes caps the size of any POST body the AS will decode. 1 MiB
// is generous for DCR (a typical request is <1 KB) and ample for token /
// revoke (smaller still); larger bodies are rejected with 413.
const maxBodyBytes = 1 << 20

// isBodyTooLarge reports whether err is a MaxBytesReader-exceeded error.
// Used by handlers that wrap r.Body with http.MaxBytesReader and want to
// distinguish that case from a generic malformed-body error.
func isBodyTooLarge(err error) bool {
	var mbe *http.MaxBytesError
	return errors.As(err, &mbe)
}
