//! radius2 is a symbolic execution framework,
//! for more info see the [README](https://github.com/aemmitt-ns/radius/blob/main/radius/README.md).

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

/// Start a symbolic execution run with `Radius`
pub use crate::radius::{Radius, RadiusOption};
/// Manage register values in `Registers`
pub use crate::registers::Registers;
/// Simulate functions by registering a `Sim`
pub use crate::sims::{Sim, SimMethod};
/// Access the program state with a `State`
pub use crate::state::State;
/// `Value` holds concrete and symbolic values
pub use crate::value::{vc, Value};
