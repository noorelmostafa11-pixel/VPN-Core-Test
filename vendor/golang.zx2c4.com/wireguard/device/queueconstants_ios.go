//go:build ios

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package device

// Fit within memory limits for iOS's Network Extension API, which has stricter requirements.
// These are vars instead of consts, because heavier network extensions might want to reduce
// them further.
var (
	QueueStagedSize                   = 16
	QueueOutboundSize                 = 64
	QueueInboundSize                  = 64
	QueueHandshakeSize                = 64
	PreallocatedBuffersPerPool uint32 = 0 // Queue and peer limits bound outstanding allocations
)

const MaxSegmentSize = 9216 // Covers the configured MTU ceiling plus encapsulation
