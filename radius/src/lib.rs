extern crate boolector;
extern crate r2pipe;
extern crate serde_json;

/// Memory used in a program state
pub mod memory;
mod operations;
/// Process the IL to execute instructions
pub mod processor;
/// Interact with the radare2 instance
pub mod r2_api;
/// Start symbolic execution for a given binary
pub mod radius;
/// Registers and their values for a given state
pub mod registers;
/// Simulated libc functions and syscalls
pub mod sims;
/// Utilities for using the SMT solver to evaluate symbolic values
pub mod solver;
/// A program state, containing the registers, memory, and solver context
pub mod state;
mod test;
/// Asbstraction for concrete and symbolic values used during execution
pub mod value;

pub use crate::radius::{Radius, RadiusOption};
pub use crate::registers::Registers;
pub use crate::sims::{Sim, SimMethod};
pub use crate::state::State;
pub use crate::value::{vc, Value};