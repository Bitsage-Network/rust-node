pub mod model_registry;
pub mod frameworks;
pub mod execution;

pub use model_registry::{ModelRegistry, ModelInfo, Framework, AICategory, HardwareSpec};
pub use frameworks::{FrameworkManager, FrameworkEnvironment, ExecutionContext};
pub use execution::{AIExecutionEngine, AIJobRequest, AIJobResult, ExecutionStatus}; 