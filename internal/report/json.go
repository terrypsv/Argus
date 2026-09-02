package report

import (
	"encoding/json"
	"io"

	"github.com/terrypsv/Argus/internal/model"
)

// JSON writes the report as indented JSON, suitable for CI pipelines,
// dashboards or diffing between runs.
func JSON(w io.Writer, rep model.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(rep)
}
