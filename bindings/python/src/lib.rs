use std::borrow::Cow;
use std::path::PathBuf;

use pyo3::create_exception;
use pyo3::exceptions::{PyException, PyValueError};
use pyo3::prelude::*;
use reader::{Error, Reader};
use serde::Serialize;

create_exception!(iplore, DatabaseError, PyException);

#[pyclass(frozen)]
struct Database {
    reader: Reader,
}

fn database_error(error: impl ToString) -> PyErr {
    DatabaseError::new_err(error.to_string())
}

fn invalid_address(address: &str) -> PyErr {
    PyValueError::new_err(format!("invalid address: {address}"))
}

fn to_python<'py>(
    python: Python<'py>,
    value: &impl Serialize,
) -> PyResult<Bound<'py, PyAny>> {
    let text = serde_json::to_string(value).map_err(database_error)?;
    python.import("json")?.call_method1("loads", (text,))
}

#[pymethods]
impl Database {
    fn lookup<'py>(
        &self,
        python: Python<'py>,
        address: &str,
    ) -> PyResult<Bound<'py, PyAny>> {
        let answer = self.reader.lookup(address).map_err(|error| match error {
            Error::InvalidAddress => invalid_address(address),
            error => database_error(error),
        })?;
        to_python(python, &answer)
    }

    fn about<'py>(&self, python: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        to_python(python, self.reader.about())
    }
}

#[pyfunction]
fn open(source: &Bound<PyAny>) -> PyResult<Database> {
    let bytes = match source.extract::<Cow<[u8]>>() {
        Ok(bytes) => bytes.into_owned(),
        Err(_) => std::fs::read(source.extract::<PathBuf>()?)?,
    };
    let reader = Reader::from_bytes(bytes).map_err(database_error)?;
    Ok(Database { reader })
}

#[pymodule]
mod iplore {
    #[pymodule_export]
    use super::{Database, DatabaseError, open};
}
