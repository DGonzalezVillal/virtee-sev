// SPDX-License-Identifier: Apache-2.0

//! First-generation SEV ABI value types.

mod platform;
mod version;

pub use platform::State;
pub use version::{Build, PlatformStatusFlags, Status, Version};
