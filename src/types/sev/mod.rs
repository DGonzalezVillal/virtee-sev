// SPDX-License-Identifier: Apache-2.0

//! First-generation SEV ABI value types.

mod platform;
mod status;

pub use platform::State;
pub use status::{PlatformStatusFlags, Status, Version};
