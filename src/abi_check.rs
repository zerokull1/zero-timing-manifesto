// Copyright (c) 2026 zerokull1 (https://github.com)
// Licensed under GPL-3.0. Unauthorized proprietary use is strictly prohibited.

use core::mem::{align_of, size_of};
use crate::ring_abi::{ZeroRingHeader};
const _: () = {
    assert!(align_of::<ZeroRingHeader>() >= 64 || size_of::<ZeroRingHeader>() >= 16);
};
