use super::field::M31;
use serde::{Serialize, Deserialize};

/// Matrix structure for ML operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Matrix {
    pub rows: usize,
    pub cols: usize,
    pub data: Vec<M31>,
}

impl Matrix {
    /// Create a new matrix with zeros
    pub fn new(rows: usize, cols: usize) -> Self {
        Self {
            rows,
            cols,
            data: vec![M31::ZERO; rows * cols],
        }
    }

    /// Create a new matrix from data
    pub fn from_data(rows: usize, cols: usize, data: Vec<M31>) -> Result<Self, String> {
        if data.len() != rows * cols {
            return Err(format!("Data length {} does not match dimensions {}x{}", data.len(), rows, cols));
        }
        Ok(Self { rows, cols, data })
    }

    /// Get element at (row, col)
    pub fn get(&self, row: usize, col: usize) -> Option<M31> {
        if row >= self.rows || col >= self.cols {
            return None;
        }
        Some(self.data[row * self.cols + col])
    }

    /// Set element at (row, col)
    pub fn set(&mut self, row: usize, col: usize, value: M31) -> Result<(), String> {
        if row >= self.rows || col >= self.cols {
            return Err("Index out of bounds".to_string());
        }
        self.data[row * self.cols + col] = value;
        Ok(())
    }

    /// Perform matrix multiplication: C = A * B
    pub fn matmul(&self, other: &Matrix) -> Result<Matrix, String> {
        if self.cols != other.rows {
            return Err(format!("Incompatible dimensions for MatMul: {}x{} * {}x{}", self.rows, self.cols, other.rows, other.cols));
        }

        let mut result = Matrix::new(self.rows, other.cols);

        for i in 0..self.rows {
            for j in 0..other.cols {
                let mut sum = M31::ZERO;
                for k in 0..self.cols {
                    let a = self.get(i, k).unwrap();
                    let b = other.get(k, j).unwrap();
                    sum = sum + (a * b);
                }
                result.set(i, j, sum)?;
            }
        }

        Ok(result)
    }

    /// Apply ReLU activation element-wise
    pub fn relu(&self) -> Matrix {
        let mut result = self.clone();
        for val in result.data.iter_mut() {
            if !val.is_positive() {
                *val = M31::ZERO;
            }
        }
        result
    }
    
    /// Apply Sigmoid activation (approximation via lookup or polynomial)
    /// For M31, we often use a piecewise linear approximation or lookup table
    /// Here we use a simple mock that clamps to [0, 1] range (0 or 1/2 or 1)
    pub fn sigmoid_approx(&self) -> Matrix {
        let mut result = self.clone();
        // Simplified sigmoid for demo: 
        // x > 2 -> 1
        // x < -2 -> 0
        // else -> 0.5 (approx)
        for val in result.data.iter_mut() {
            // M31 doesn't have standard ordering for negatives like i32
            // Assume "small" positive is > 0, "large" positive is < 0
            if val.is_positive() {
                // Positive
                if val.value() > 2 {
                    *val = M31::ONE;
                } else {
                    // 0.5 approx (inverse of 2)
                    *val = M31::from(2).inverse().unwrap_or(M31::ZERO);
                }
            } else {
                // Negative
                // If magnitude is large (e.g. -1, -2), close to 0
                // For now just 0
                *val = M31::ZERO;
            }
        }
        result
    }
}

