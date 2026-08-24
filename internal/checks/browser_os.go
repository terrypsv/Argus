// Copyright (c) 2026 Terry Passave. All rights reserved.
// Proprietary and confidential. Unauthorized use is prohibited.

package checks

import "runtime"

// runtimeGOOS is indirected so the profile discovery can be exercised for
// every platform from a single test run.
var runtimeGOOS = func() string { return runtime.GOOS }
