extern crate boolector;
extern crate r2pipe;
extern crate serde_json;

pub mod memory;
pub mod operations;
pub mod processor;
pub mod r2_api;
pub mod radius;
pub mod registers;
pub mod sims;
pub mod solver;
pub mod state;
pub mod test;
pub mod value;

pub use crate::radius::{Radius, RadiusOption};
pub use crate::state::State;
pub use crate::value::{Value, vc};

use mimalloc::MiMalloc;
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;