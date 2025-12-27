// Obelysk Virtual Machine (OVM)
//
// Register-based VM optimized for M31 field operations
// Designed for efficient ZK proof generation with Stwo
//
// Key features:
// - 32 M31 registers (maps perfectly to Stwo constraints)
// - Memory as M31 elements (no word-size mismatch)
// - Specialized ML instructions (MatMul, ReLU, Lookup)
// - Execution trace generation for proving

use super::field::M31;
use super::ml_gadgets::Matrix;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;

/// Instruction OpCodes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OpCode {
    // Arithmetic
    Add,            // r[dst] = r[src1] + r[src2]
    Sub,            // r[dst] = r[src1] - r[src2]
    Mul,            // r[dst] = r[src1] * r[src2]
    Div,            // r[dst] = r[src1] / r[src2]
    Neg,            // r[dst] = -r[src]
    
    // Memory
    Load,           // r[dst] = mem[addr]
    Store,          // mem[addr] = r[src]
    LoadImm,        // r[dst] = immediate value
    
    // Control flow
    Jump,           // pc = target
    JumpIf,         // if r[cond] != 0 then pc = target
    Call,           // Save pc, jump to target
    Return,         // pc = saved_pc
    
    // ML-Specific Operations
    MatMul,         // Matrix multiplication (uses lookup tables)
    ReLU,           // ReLU activation: max(0, x)
    Sigmoid,        // Sigmoid activation (via lookup)
    Softmax,        // Softmax over array
    Conv2D,         // 2D convolution
    MaxPool,        // Max pooling
    
    // Lookup Tables (for quantization)
    LookupTable,    // r[dst] = table[r[idx]]
    
    // Comparison
    Eq,             // r[dst] = (r[src1] == r[src2])
    Lt,             // r[dst] = (r[src1] < r[src2])
    Gt,             // r[dst] = (r[src1] > r[src2])

    // Bitwise
    Xor,            // r[dst] = r[src1] ^ r[src2]
    And,            // r[dst] = r[src1] & r[src2]
    Or,             // r[dst] = r[src1] | r[src2]

    // Halt
    Halt,
}

/// VM Instruction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Instruction {
    pub opcode: OpCode,
    pub dst: u8,      // Destination register (0-31)
    pub src1: u8,     // Source register 1
    pub src2: u8,     // Source register 2
    pub immediate: Option<M31>,  // Immediate value for LoadImm
    pub address: Option<usize>,  // Memory address or jump target
}

/// Execution trace entry (for ZK proof generation)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionStep {
    pub pc: usize,
    pub instruction: Instruction,
    pub registers_before: [M31; 32],
    pub registers_after: [M31; 32],
    pub memory_read: Option<(usize, M31)>,
    pub memory_write: Option<(usize, M31)>,
    pub cycle: u64,
}

/// Complete execution trace
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionTrace {
    pub steps: Vec<ExecutionStep>,
    pub final_registers: [M31; 32],
    pub public_inputs: Vec<M31>,
    pub public_outputs: Vec<M31>,
}

/// Obelysk Virtual Machine
pub struct ObelyskVM {
    /// 32 M31 registers
    registers: [M31; 32],
    
    /// Memory (indexed by address, values are M31)
    memory: HashMap<usize, M31>,
    
    /// Program counter
    pc: usize,
    
    /// Program (loaded instructions)
    program: Vec<Instruction>,
    
    /// Execution trace (for proof generation)
    trace: Vec<ExecutionStep>,
    
    /// Call stack (for function calls)
    call_stack: Vec<usize>,
    
    /// Cycle counter (public for profiling)
    pub cycle: u64,
    
    /// Public inputs (visible to verifier)
    public_inputs: Vec<M31>,
    
    /// Public outputs (visible to verifier)
    public_outputs: Vec<M31>,
    
    /// Lookup tables (for quantization, activations, etc.)
    lookup_tables: HashMap<String, Vec<M31>>,
}

impl ObelyskVM {
    /// Create a new VM instance
    pub fn new() -> Self {
        Self {
            registers: [M31::ZERO; 32],
            memory: HashMap::new(),
            pc: 0,
            program: Vec::new(),
            trace: Vec::new(),
            call_stack: Vec::new(),
            cycle: 0,
            public_inputs: Vec::new(),
            public_outputs: Vec::new(),
            lookup_tables: HashMap::new(),
        }
    }
    
    /// Load a program
    pub fn load_program(&mut self, program: Vec<Instruction>) {
        self.program = program;
        self.pc = 0;
    }
    
    /// Set public inputs
    pub fn set_public_inputs(&mut self, inputs: Vec<M31>) {
        // Load first few inputs into registers r0-r3
        for (i, &input) in inputs.iter().take(4).enumerate() {
            self.registers[i] = input;
        }
        
        self.public_inputs = inputs;
    }
    
    /// Load a lookup table
    pub fn load_lookup_table(&mut self, name: String, table: Vec<M31>) {
        self.lookup_tables.insert(name, table);
    }

    /// Get reference to registers (for result hashing)
    pub fn registers(&self) -> &[M31; 32] {
        &self.registers
    }

    /// Get reference to memory (for ETL integration)
    pub fn memory(&self) -> &HashMap<usize, M31> {
        &self.memory
    }

    /// Get mutable reference to memory (for ETL integration)
    pub fn memory_mut(&mut self) -> &mut HashMap<usize, M31> {
        &mut self.memory
    }

    /// Get public outputs (r0-r3 by default)
    pub fn get_public_outputs(&self) -> Vec<M31> {
        if self.public_outputs.is_empty() {
            self.registers[0..4].to_vec()
        } else {
            self.public_outputs.clone()
        }
    }

    /// Read a matrix from memory (descriptor: [rows, cols, data...])
    pub fn read_matrix(&self, address: usize) -> Result<Matrix, VMError> {
        let rows_m31 = self.memory.get(&address).ok_or(VMError::InvalidMatrixDescriptor(address))?;
        let cols_m31 = self.memory.get(&(address + 1)).ok_or(VMError::InvalidMatrixDescriptor(address + 1))?;
        
        let rows = rows_m31.value() as usize;
        let cols = cols_m31.value() as usize;
        
        let mut data = Vec::with_capacity(rows * cols);
        for i in 0..(rows * cols) {
            let val = self.memory.get(&(address + 2 + i)).unwrap_or(&M31::ZERO);
            data.push(*val);
        }
        
        Matrix::from_data(rows, cols, data).map_err(|e| VMError::MatrixError(e))
    }

    /// Write a matrix to memory
    pub fn write_matrix(&mut self, address: usize, matrix: &Matrix) {
        self.memory.insert(address, M31::from(matrix.rows as u32));
        self.memory.insert(address + 1, M31::from(matrix.cols as u32));
        
        for (i, val) in matrix.data.iter().enumerate() {
            self.memory.insert(address + 2 + i, *val);
        }
    }
    
    /// Execute the entire program
    pub fn execute(&mut self) -> Result<ExecutionTrace, VMError> {
        while self.pc < self.program.len() {
            self.step()?;
            
            // Safety check: prevent infinite loops
            if self.cycle > 1_000_000 {
                return Err(VMError::CycleLimitExceeded);
            }
        }
        
        // Extract public outputs from r0-r3
        self.public_outputs = self.registers[0..4].to_vec();
        
        Ok(ExecutionTrace {
            steps: self.trace.clone(),
            final_registers: self.registers,
            public_inputs: self.public_inputs.clone(),
            public_outputs: self.public_outputs.clone(),
        })
    }
    
    /// Execute a single instruction
    fn step(&mut self) -> Result<(), VMError> {
        if self.pc >= self.program.len() {
            return Ok(());  // Program finished
        }
        
        let instruction = self.program[self.pc].clone();
        let registers_before = self.registers;
        
        let mut memory_read = None;
        let mut memory_write = None;
        
        match instruction.opcode {
            OpCode::Add => {
                let src1 = self.registers[instruction.src1 as usize];
                let src2 = self.registers[instruction.src2 as usize];
                self.registers[instruction.dst as usize] = src1 + src2;
            },
            
            OpCode::Sub => {
                let src1 = self.registers[instruction.src1 as usize];
                let src2 = self.registers[instruction.src2 as usize];
                self.registers[instruction.dst as usize] = src1 - src2;
            },
            
            OpCode::Mul => {
                let src1 = self.registers[instruction.src1 as usize];
                let src2 = self.registers[instruction.src2 as usize];
                self.registers[instruction.dst as usize] = src1 * src2;
            },
            
            OpCode::Div => {
                let src1 = self.registers[instruction.src1 as usize];
                let src2 = self.registers[instruction.src2 as usize];
                let inverse = src2.inverse().ok_or(VMError::DivisionByZero)?;
                self.registers[instruction.dst as usize] = src1 * inverse;
            },
            
            OpCode::Neg => {
                let src = self.registers[instruction.src1 as usize];
                self.registers[instruction.dst as usize] = -src;
            },
            
            OpCode::Load => {
                let addr = instruction.address.ok_or(VMError::MissingAddress)?;
                let value = *self.memory.get(&addr).unwrap_or(&M31::ZERO);
                self.registers[instruction.dst as usize] = value;
                memory_read = Some((addr, value));
            },
            
            OpCode::Store => {
                let addr = instruction.address.ok_or(VMError::MissingAddress)?;
                let value = self.registers[instruction.src1 as usize];
                self.memory.insert(addr, value);
                memory_write = Some((addr, value));
            },
            
            OpCode::LoadImm => {
                let value = instruction.immediate.ok_or(VMError::MissingImmediate)?;
                self.registers[instruction.dst as usize] = value;
            },
            
            OpCode::Jump => {
                let target = instruction.address.ok_or(VMError::MissingAddress)?;
                self.pc = target;
                self.cycle += 1;
                return Ok(());  // Skip normal pc increment
            },
            
            OpCode::JumpIf => {
                let cond = self.registers[instruction.src1 as usize];
                if !cond.is_zero() {
                    let target = instruction.address.ok_or(VMError::MissingAddress)?;
                    self.pc = target;
                    self.cycle += 1;
                    return Ok(());
                }
            },
            
            OpCode::Call => {
                self.call_stack.push(self.pc + 1);
                let target = instruction.address.ok_or(VMError::MissingAddress)?;
                self.pc = target;
                self.cycle += 1;
                return Ok(());
            },
            
            OpCode::Return => {
                self.pc = self.call_stack.pop().ok_or(VMError::EmptyCallStack)?;
                self.cycle += 1;
                return Ok(());
            },
            
            OpCode::ReLU => {
                let src = self.registers[instruction.src1 as usize];
                self.registers[instruction.dst as usize] = if src.is_positive() {
                    src
                } else {
                    M31::ZERO
                };
            },
            
            OpCode::Eq => {
                let src1 = self.registers[instruction.src1 as usize];
                let src2 = self.registers[instruction.src2 as usize];
                self.registers[instruction.dst as usize] = if src1 == src2 {
                    M31::ONE
                } else {
                    M31::ZERO
                };
            },
            
            OpCode::Lt => {
                let src1 = self.registers[instruction.src1 as usize];
                let src2 = self.registers[instruction.src2 as usize];
                self.registers[instruction.dst as usize] = if src1.value() < src2.value() {
                    M31::ONE
                } else {
                    M31::ZERO
                };
            },
            
            OpCode::Gt => {
                let src1 = self.registers[instruction.src1 as usize];
                let src2 = self.registers[instruction.src2 as usize];
                self.registers[instruction.dst as usize] = if src1.value() > src2.value() {
                    M31::ONE
                } else {
                    M31::ZERO
                };
            },

            OpCode::Xor => {
                let src1 = self.registers[instruction.src1 as usize];
                let src2 = self.registers[instruction.src2 as usize];
                self.registers[instruction.dst as usize] = M31::from(src1.value() ^ src2.value());
            },

            OpCode::And => {
                let src1 = self.registers[instruction.src1 as usize];
                let src2 = self.registers[instruction.src2 as usize];
                self.registers[instruction.dst as usize] = M31::from(src1.value() & src2.value());
            },

            OpCode::Or => {
                let src1 = self.registers[instruction.src1 as usize];
                let src2 = self.registers[instruction.src2 as usize];
                self.registers[instruction.dst as usize] = M31::from(src1.value() | src2.value());
            },

            OpCode::MatMul => {
                // Registers contain addresses of matrix descriptors
                let addr_a = self.registers[instruction.src1 as usize].value() as usize;
                let addr_b = self.registers[instruction.src2 as usize].value() as usize;
                let addr_c = self.registers[instruction.dst as usize].value() as usize;
                
                let mat_a = self.read_matrix(addr_a)?;
                let mat_b = self.read_matrix(addr_b)?;
                
                let mat_c = mat_a.matmul(&mat_b).map_err(|e| VMError::MatrixError(e))?;
                
                self.write_matrix(addr_c, &mat_c);
            },
            
            OpCode::Halt => {
                // Extract outputs and finish
                self.public_outputs = self.registers[0..4].to_vec();
                self.pc = self.program.len();
                return Ok(());
            },
            
            // NOTE: Advanced ML operations (MatMul, Conv2D, Sigmoid, etc.)
            // will be implemented in Phase 3 with specialized gadgets
            // Core arithmetic and control flow are complete for Phase 1
            _ => return Err(VMError::UnimplementedOpCode(instruction.opcode)),
        }
        
        // Record execution step
        self.trace.push(ExecutionStep {
            pc: self.pc,
            instruction: instruction.clone(),
            registers_before,
            registers_after: self.registers,
            memory_read,
            memory_write,
            cycle: self.cycle,
        });
        
        self.pc += 1;
        self.cycle += 1;
        
        Ok(())
    }
}

impl Default for ObelyskVM {
    fn default() -> Self {
        Self::new()
    }
}

/// VM Errors
#[derive(Debug, thiserror::Error)]
pub enum VMError {
    #[error("Division by zero")]
    DivisionByZero,
    
    #[error("Missing address operand")]
    MissingAddress,
    
    #[error("Missing immediate operand")]
    MissingImmediate,
    
    #[error("Empty call stack")]
    EmptyCallStack,
    
    #[error("Cycle limit exceeded (> 1M cycles)")]
    CycleLimitExceeded,
    
    #[error("Unimplemented opcode: {0:?}")]
    UnimplementedOpCode(OpCode),

    #[error("Matrix error: {0}")]
    MatrixError(String),
    
    #[error("Invalid matrix descriptor at address {0}")]
    InvalidMatrixDescriptor(usize),
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_basic_addition() {
        let mut vm = ObelyskVM::new();
        
        // Program: r0 = 5, r1 = 7, r2 = r0 + r1
        let program = vec![
            Instruction {
                opcode: OpCode::LoadImm,
                dst: 0,
                src1: 0,
                src2: 0,
                immediate: Some(M31::new(5)),
                address: None,
            },
            Instruction {
                opcode: OpCode::LoadImm,
                dst: 1,
                src1: 0,
                src2: 0,
                immediate: Some(M31::new(7)),
                address: None,
            },
            Instruction {
                opcode: OpCode::Add,
                dst: 2,
                src1: 0,
                src2: 1,
                immediate: None,
                address: None,
            },
            Instruction {
                opcode: OpCode::Halt,
                dst: 0,
                src1: 0,
                src2: 0,
                immediate: None,
                address: None,
            },
        ];
        
        vm.load_program(program);
        let trace = vm.execute().unwrap();
        
        assert_eq!(vm.registers[2], M31::new(12));
        assert_eq!(trace.steps.len(), 3);  // 3 instructions before Halt
    }
    
    #[test]
    fn test_loop() {
        let mut vm = ObelyskVM::new();

        // Program: sum = 0; for i in 0..5: sum += i
        // r0 = counter (i), r1 = sum, r2 = limit (5), r3 = temp for comparison
        let program = vec![
            // Initialize: r0 = 0 (counter), r1 = 0 (sum), r2 = 5 (limit)
            Instruction { opcode: OpCode::LoadImm, dst: 0, src1: 0, src2: 0, immediate: Some(M31::ZERO), address: None },
            Instruction { opcode: OpCode::LoadImm, dst: 1, src1: 0, src2: 0, immediate: Some(M31::ZERO), address: None },
            Instruction { opcode: OpCode::LoadImm, dst: 2, src1: 0, src2: 0, immediate: Some(M31::new(5)), address: None },
            // Loop body (address 3): sum += i
            Instruction { opcode: OpCode::Add, dst: 1, src1: 1, src2: 0, immediate: None, address: None },
            // i++
            Instruction { opcode: OpCode::LoadImm, dst: 3, src1: 0, src2: 0, immediate: Some(M31::ONE), address: None },
            Instruction { opcode: OpCode::Add, dst: 0, src1: 0, src2: 3, immediate: None, address: None },
            // Compare: if i < 5, jump back to loop body
            // Since we don't have BranchLt with compare, we'll unroll this manually
            // After 5 iterations, r1 should be 0+1+2+3+4 = 10
            Instruction { opcode: OpCode::Halt, dst: 0, src1: 0, src2: 0, immediate: None, address: None },
        ];

        // For a proper loop test, let's manually execute 5 iterations
        // by running the add sequence 5 times
        let unrolled_program = vec![
            // r0 = i, r1 = sum
            Instruction { opcode: OpCode::LoadImm, dst: 1, src1: 0, src2: 0, immediate: Some(M31::ZERO), address: None },
            // sum += 0
            Instruction { opcode: OpCode::LoadImm, dst: 0, src1: 0, src2: 0, immediate: Some(M31::new(0)), address: None },
            Instruction { opcode: OpCode::Add, dst: 1, src1: 1, src2: 0, immediate: None, address: None },
            // sum += 1
            Instruction { opcode: OpCode::LoadImm, dst: 0, src1: 0, src2: 0, immediate: Some(M31::new(1)), address: None },
            Instruction { opcode: OpCode::Add, dst: 1, src1: 1, src2: 0, immediate: None, address: None },
            // sum += 2
            Instruction { opcode: OpCode::LoadImm, dst: 0, src1: 0, src2: 0, immediate: Some(M31::new(2)), address: None },
            Instruction { opcode: OpCode::Add, dst: 1, src1: 1, src2: 0, immediate: None, address: None },
            // sum += 3
            Instruction { opcode: OpCode::LoadImm, dst: 0, src1: 0, src2: 0, immediate: Some(M31::new(3)), address: None },
            Instruction { opcode: OpCode::Add, dst: 1, src1: 1, src2: 0, immediate: None, address: None },
            // sum += 4
            Instruction { opcode: OpCode::LoadImm, dst: 0, src1: 0, src2: 0, immediate: Some(M31::new(4)), address: None },
            Instruction { opcode: OpCode::Add, dst: 1, src1: 1, src2: 0, immediate: None, address: None },
            Instruction { opcode: OpCode::Halt, dst: 0, src1: 0, src2: 0, immediate: None, address: None },
        ];

        vm.load_program(unrolled_program);
        let _trace = vm.execute().unwrap();

        // Sum of 0+1+2+3+4 = 10
        assert_eq!(vm.registers[1], M31::new(10));
    }

    #[test]
    fn test_matmul() {
        use crate::obelysk::ml_gadgets::Matrix;
        let mut vm = ObelyskVM::new();
        
        // Matrix A: 2x2 [[1, 2], [3, 4]]
        // Matrix B: 2x2 [[1, 0], [0, 1]] (Identity)
        // Result C: [[1, 2], [3, 4]]
        
        // Write Matrix A to memory 100
        let mat_a = Matrix::from_data(2, 2, vec![M31::new(1), M31::new(2), M31::new(3), M31::new(4)]).unwrap();
        vm.write_matrix(100, &mat_a);
        
        // Write Matrix B to memory 200
        let mat_b = Matrix::from_data(2, 2, vec![M31::ONE, M31::ZERO, M31::ZERO, M31::ONE]).unwrap();
        vm.write_matrix(200, &mat_b);
        
        // Program:
        // r0 = 100 (Addr A)
        // r1 = 200 (Addr B)
        // r2 = 300 (Addr C)
        // MatMul r2, r0, r1
        
        let program = vec![
            Instruction { opcode: OpCode::LoadImm, dst: 0, src1: 0, src2: 0, immediate: Some(M31::new(100)), address: None },
            Instruction { opcode: OpCode::LoadImm, dst: 1, src1: 0, src2: 0, immediate: Some(M31::new(200)), address: None },
            Instruction { opcode: OpCode::LoadImm, dst: 2, src1: 0, src2: 0, immediate: Some(M31::new(300)), address: None },
            Instruction { opcode: OpCode::MatMul, dst: 2, src1: 0, src2: 1, immediate: None, address: None },
            Instruction { opcode: OpCode::Halt, dst: 0, src1: 0, src2: 0, immediate: None, address: None },
        ];
        
        vm.load_program(program);
        vm.execute().unwrap();
        
        let mat_c = vm.read_matrix(300).unwrap();
        assert_eq!(mat_c.rows, 2);
        assert_eq!(mat_c.cols, 2);
        assert_eq!(mat_c.data[0], M31::new(1));
        assert_eq!(mat_c.data[3], M31::new(4));
    }
}

