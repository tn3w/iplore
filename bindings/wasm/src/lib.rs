use std::cell::{OnceCell, RefCell};

use reader::{Error, Reader};

#[repr(u32)]
enum Status {
    Ok,
    InvalidAddress,
    Corrupt,
    NotLoaded,
    AlreadyLoaded,
}

thread_local! {
    static READER: OnceCell<Reader> = const { OnceCell::new() };
    static OUTPUT: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

fn take(pointer: *mut u8, length: usize) -> Vec<u8> {
    let slice = std::ptr::slice_from_raw_parts_mut(pointer, length);
    unsafe { Box::from_raw(slice) }.into_vec()
}

fn respond(status: Status, text: String) -> u32 {
    OUTPUT.set(text.into_bytes());
    status as u32
}

fn fail(error: Error) -> u32 {
    match error {
        Error::InvalidAddress => respond(Status::InvalidAddress, error.to_string()),
        Error::Corrupt(_) => respond(Status::Corrupt, error.to_string()),
    }
}

fn answer(reader: &Reader, address: &str) -> Result<String, Error> {
    let answer = reader.lookup(address)?;
    serde_json::to_string(&answer).map_err(|error| Error::Corrupt(error.to_string()))
}

#[unsafe(no_mangle)]
pub extern "C" fn allocate(length: usize) -> *mut u8 {
    Box::into_raw(vec![0u8; length].into_boxed_slice()).cast()
}

#[unsafe(no_mangle)]
pub extern "C" fn output() -> *const u8 {
    OUTPUT.with_borrow(|bytes| bytes.as_ptr())
}

#[unsafe(no_mangle)]
pub extern "C" fn output_length() -> usize {
    OUTPUT.with_borrow(|bytes| bytes.len())
}

#[unsafe(no_mangle)]
pub extern "C" fn load(pointer: *mut u8, length: usize) -> u32 {
    let bytes = take(pointer, length);
    if READER.with(|slot| slot.get().is_some()) {
        return respond(Status::AlreadyLoaded, "a database is already loaded".into());
    }
    match Reader::from_bytes(bytes) {
        Ok(reader) => {
            READER.with(|slot| slot.set(reader).ok());
            respond(Status::Ok, String::new())
        }
        Err(error) => fail(error),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn lookup(pointer: *mut u8, length: usize) -> u32 {
    let address = String::from_utf8_lossy(&take(pointer, length)).into_owned();
    READER.with(|slot| match slot.get() {
        None => respond(Status::NotLoaded, "no database is loaded".into()),
        Some(reader) => match answer(reader, &address) {
            Ok(text) => respond(Status::Ok, text),
            Err(error) => fail(error),
        },
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn about() -> u32 {
    READER.with(|slot| match slot.get() {
        None => respond(Status::NotLoaded, "no database is loaded".into()),
        Some(reader) => respond(Status::Ok, reader.about().to_string()),
    })
}
