//! FFI bindings and Rust wrappers for [libfswatch](https://github.com/emcrisostomo/fswatch).

#![allow(non_camel_case_types)]

pub extern crate fswatch_sys;
extern crate libc;
#[macro_use]
extern crate cfg_if;
#[cfg(feature = "use_time")]
extern crate time;

pub use fswatch_sys as ffi;

use libc::{c_uint, c_void, c_double};
use std::ops::Drop;
use std::ffi::{CString, CStr};
use std::path::{Path, PathBuf};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::mpsc::{Sender, Receiver, channel};
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(feature = "fswatch_1_10_0")]
use std::ptr::Unique;

#[cfg(test)]
mod test;

type FswResult<T> = Result<T, FswError>;

/// An error in the library.
#[derive(Debug, PartialEq)]
pub enum FswError {
  /// An error from fswatch.
  FromFsw(FswStatus),
  /// An error encountered when working with C strings.
  NulError(std::ffi::NulError),
  /// An error indicating that required parameters were missing.
  MissingRequiredParameters
}

/// Status codes from fswatch.
///
/// Most operations return a status code, either `Ok` or an error. A successful operation that
/// returns `Ok` is represented by returning `Ok(T)`, where `T` is data returned, if any. If no data
/// is returned, `()` is `T`.
///
/// Errors are represented by `Err(FswStatus)`, with the status returned by the operation being
/// directly available inside the `Err`.
#[derive(Debug, PartialEq)]
pub enum FswStatus {
  /// No error.
  Ok,
  /// Occasionally used by the Rust library to denote errors without status codes in fswatch.
  UnknownError,
  SessionUnknown,
  MonitorAlreadyExists,
  Memory,
  UnknownMonitorType,
  CallbackNotSet,
  PathsNotSet,
  MissingContext,
  InvalidPath,
  InvalidCallback,
  InvalidLatency,
  InvalidRegex,
  MonitorAlreadyRunning,
  UnknownValue,
  InvalidProperty
}

impl From<ffi::FSW_STATUS> for FswStatus {
  /// Converts from the `FSW_STATUS` type into the Rust `FswStatus`.
  ///
  /// This should never need to be used if utilizing the Rust wrappers. If given an invalid code,
  /// this will default to `UnknownError`.
  fn from(status: ffi::FSW_STATUS) -> FswStatus {
    match status {
      ffi::FSW_OK => FswStatus::Ok,
      ffi::FSW_ERR_SESSION_UNKNOWN => FswStatus::SessionUnknown,
      ffi::FSW_ERR_MONITOR_ALREADY_EXISTS => FswStatus::MonitorAlreadyExists,
      ffi::FSW_ERR_MEMORY => FswStatus::Memory,
      ffi::FSW_ERR_UNKNOWN_MONITOR_TYPE => FswStatus::UnknownMonitorType,
      ffi::FSW_ERR_CALLBACK_NOT_SET => FswStatus::CallbackNotSet,
      ffi::FSW_ERR_PATHS_NOT_SET => FswStatus::PathsNotSet,
      ffi::FSW_ERR_MISSING_CONTEXT => FswStatus::MissingContext,
      ffi::FSW_ERR_INVALID_PATH => FswStatus::InvalidPath,
      ffi::FSW_ERR_INVALID_CALLBACK => FswStatus::InvalidCallback,
      ffi::FSW_ERR_INVALID_LATENCY => FswStatus::InvalidLatency,
      ffi::FSW_ERR_INVALID_REGEX => FswStatus::InvalidRegex,
      ffi::FSW_ERR_MONITOR_ALREADY_RUNNING => FswStatus::MonitorAlreadyRunning,
      ffi::FSW_ERR_UNKNOWN_VALUE => FswStatus::UnknownValue,
      ffi::FSW_ERR_INVALID_PROPERTY => FswStatus::InvalidProperty,
      ffi::FSW_ERR_UNKNOWN_ERROR | _ => FswStatus::UnknownError
    }
  }
}

/// The various possible monitors that fswatch can utilize.
#[derive(Debug, PartialEq)]
pub enum FswMonitorType {
  SystemDefault,
  FSEvents,
  KQueue,
  INotify,
  Windows,
  Poll,
  Fen
}

impl From<FswMonitorType> for ffi::fsw_monitor_type {
  fn from(monitor_type: FswMonitorType) -> ffi::fsw_monitor_type {
    match monitor_type {
      FswMonitorType::SystemDefault => ffi::fsw_monitor_type::system_default_monitor_type,
      FswMonitorType::FSEvents => ffi::fsw_monitor_type::fsevents_monitor_type,
      FswMonitorType::KQueue => ffi::fsw_monitor_type::kqueue_monitor_type,
      FswMonitorType::INotify => ffi::fsw_monitor_type::inotify_monitor_type,
      FswMonitorType::Windows => ffi::fsw_monitor_type::windows_monitor_type,
      FswMonitorType::Poll => ffi::fsw_monitor_type::poll_monitor_type,
      FswMonitorType::Fen => ffi::fsw_monitor_type::fen_monitor_type
    }
  }
}

/// Flags denoting the operation(s) within an event.
#[derive(Debug, PartialEq, Clone)]
pub enum FswEventFlag {
  NoOp,
  PlatformSpecific,
  Created,
  Updated,
  Removed,
  Renamed,
  OwnerModified,
  AttributeModified,
  MovedFrom,
  MovedTo,
  IsFile,
  IsDir,
  IsSymLink,
  Link,
  Overflow
}

impl From<FswEventFlag> for ffi::fsw_event_flag {
  fn from(flag: FswEventFlag) -> ffi::fsw_event_flag {
    match flag {
      FswEventFlag::NoOp => ffi::fsw_event_flag::NoOp,
      FswEventFlag::PlatformSpecific => ffi::fsw_event_flag::PlatformSpecific,
      FswEventFlag::Created => ffi::fsw_event_flag::Created,
      FswEventFlag::Updated => ffi::fsw_event_flag::Updated,
      FswEventFlag::Removed => ffi::fsw_event_flag::Removed,
      FswEventFlag::Renamed => ffi::fsw_event_flag::Renamed,
      FswEventFlag::OwnerModified => ffi::fsw_event_flag::OwnerModified,
      FswEventFlag::AttributeModified => ffi::fsw_event_flag::AttributeModified,
      FswEventFlag::MovedFrom => ffi::fsw_event_flag::MovedFrom,
      FswEventFlag::MovedTo => ffi::fsw_event_flag::MovedTo,
      FswEventFlag::IsFile => ffi::fsw_event_flag::IsFile,
      FswEventFlag::IsDir => ffi::fsw_event_flag::IsDir,
      FswEventFlag::IsSymLink => ffi::fsw_event_flag::IsSymLink,
      FswEventFlag::Link => ffi::fsw_event_flag::Link,
      FswEventFlag::Overflow => ffi::fsw_event_flag::Overflow
    }
  }
}

impl<'a> From<&'a ffi::fsw_event_flag> for FswEventFlag {
  fn from(flag: &'a ffi::fsw_event_flag) -> FswEventFlag {
    match *flag {
      ffi::fsw_event_flag::NoOp => FswEventFlag::NoOp,
      ffi::fsw_event_flag::PlatformSpecific => FswEventFlag::PlatformSpecific,
      ffi::fsw_event_flag::Created => FswEventFlag::Created,
      ffi::fsw_event_flag::Updated => FswEventFlag::Updated,
      ffi::fsw_event_flag::Removed => FswEventFlag::Removed,
      ffi::fsw_event_flag::Renamed => FswEventFlag::Renamed,
      ffi::fsw_event_flag::OwnerModified => FswEventFlag::OwnerModified,
      ffi::fsw_event_flag::AttributeModified => FswEventFlag::AttributeModified,
      ffi::fsw_event_flag::MovedFrom => FswEventFlag::MovedFrom,
      ffi::fsw_event_flag::MovedTo => FswEventFlag::MovedTo,
      ffi::fsw_event_flag::IsFile => FswEventFlag::IsFile,
      ffi::fsw_event_flag::IsDir => FswEventFlag::IsDir,
      ffi::fsw_event_flag::IsSymLink => FswEventFlag::IsSymLink,
      ffi::fsw_event_flag::Link => FswEventFlag::Link,
      ffi::fsw_event_flag::Overflow => FswEventFlag::Overflow
    }
  }
}

/// A monitor filter.
#[derive(Debug)]
pub struct FswMonitorFilter {
  /// A regular expression to match paths against.
  pub text: String,
  /// The type of filter.
  pub filter_type: FswFilterType,
  /// Whether the regular expression in `text` should be case sensitive.
  pub case_sensitive: bool,
  /// Whether the regular expression in `text` is an extended regular expression.
  pub extended: bool
}

impl FswMonitorFilter {
  pub fn new<S>(text: S, filter_type: FswFilterType, case_sensitive: bool, extended: bool) -> Self
    where S: AsRef<str>
  {
    FswMonitorFilter {
      text: text.as_ref().to_owned(),
      filter_type: filter_type,
      case_sensitive: case_sensitive,
      extended: extended
    }
  }
}

/// A filter type.
#[derive(Debug)]
pub enum FswFilterType {
  Include,
  Exclude
}

impl From<FswFilterType> for ffi::fsw_filter_type {
  fn from(filter_type: FswFilterType) -> ffi::fsw_filter_type {
    match filter_type {
      FswFilterType::Include => ffi::fsw_filter_type::filter_include,
      FswFilterType::Exclude => ffi::fsw_filter_type::filter_exclude
    }
  }
}

/// An event from fswatch.
///
/// This is most likely what will be used most in this library. No changes done to this struct or
/// its fields will affect libfswatch. All the data is a copy of the original, to ensure no memory
/// invalidation in C.
#[derive(Debug)]
pub struct FswEvent {
  /// The file path for this event.
  pub path: String,
  /// The time at which this event took place.
  #[cfg(feature = "use_time")]
  pub time: time::Tm,
  #[cfg(not(feature = "use_time"))]
  pub time: i64,
  /// The flags set on this event.
  pub flags: Vec<FswEventFlag>
}

/// Static methods for fswatch.
pub struct Fsw;

impl Fsw {
  /// Initialize the library. This must be called once before anything can be done with the library.
  pub fn init_library() -> FswResult<()> {
    let result = unsafe { ffi::fsw_init_library() };
    FswSession::map_result((), result)
  }

  /// Gets the last error that occurred in the library.
  pub fn last_error() -> FswStatus {
    let result = unsafe { ffi::fsw_last_error() };
    result.into()
  }

  pub fn verbose() -> bool {
    unsafe { ffi::fsw_is_verbose() }
  }

  pub fn set_verbose(verbose: bool) {
    unsafe { ffi::fsw_set_verbose(verbose) };
  }
}

/// A builder for [`FswSession`](struct.FswSession.html).
///
/// This struct saves all the options passed to it by the builder methods, which means it is safe
/// to call the builder methods multiple times, as nothing will be passed to the C API until
/// [`build`](#method.build) is called.
#[derive(Debug)]
pub struct FswSessionBuilder {
  paths: Vec<PathBuf>,
  monitor_type: FswMonitorType,
  properties: HashMap<String, String>,
  overflow: Option<bool>,
  latency: Option<c_double>,
  recursive: Option<bool>,
  directory_only: Option<bool>,
  follow_symlinks: Option<bool>,
  event_type_filters: Vec<FswEventFlag>,
  filters: Vec<FswMonitorFilter>
}

impl FswSessionBuilder {

  /// Creates an empty builder, not requiring `paths` to be set.
  ///
  /// This is mainly useful when constructing an `FswSession` for use as an iterator.
  pub fn empty() -> Self {
    FswSessionBuilder::create(None)
  }

  /// Make a new builder with the required variables.
  pub fn new<P>(paths: Vec<P>) -> Self
    where P: AsRef<Path>
  {
    let paths = paths.iter().map(|x| x.as_ref().to_owned()).collect();
    FswSessionBuilder::create(Some(paths))
  }

  fn create(paths: Option<Vec<PathBuf>>) -> Self {
    FswSessionBuilder {
      paths: paths.unwrap_or_else(Vec::new),
      monitor_type: FswMonitorType::SystemDefault,
      properties: Default::default(),
      overflow: Default::default(),
      latency: Default::default(),
      recursive: Default::default(),
      directory_only: Default::default(),
      follow_symlinks: Default::default(),
      event_type_filters: Default::default(),
      filters: Default::default()
    }
  }

  /// Build the `FswSession`, applying all specified options before passing ownership to the caller.
  ///
  /// If any errors occur while applying options, they are propagated up.
  pub fn build(self) -> FswResult<FswSession> {
    let session = FswSession::new(self.monitor_type)?;
    for path in self.paths {
      session.add_path(path)?;
    }
    for (name, value) in self.properties {
      session.add_property(&name, &value)?;
    }
    if let Some(overflow) = self.overflow {
      session.set_allow_overflow(overflow)?;
    }
    if let Some(latency) = self.latency {
      session.set_latency(latency)?;
    }
    if let Some(recursive) = self.recursive {
      session.set_recursive(recursive)?;
    }
    if let Some(directory_only) = self.directory_only {
      session.set_directory_only(directory_only)?;
    }
    if let Some(follow_symlinks) = self.follow_symlinks {
      session.set_follow_symlinks(follow_symlinks)?;
    }
    for event_type in self.event_type_filters {
      session.add_event_type_filter(event_type)?;
    }
    for filter in self.filters {
      session.add_filter(filter)?;
    }
    Ok(session)
  }

  /// Build the `FswSession` with a callback, applying all specified options before passing
  /// ownership to the caller.
  ///
  /// If any errors occur while applying options, they are propagated up.
  pub fn build_callback<F>(self, callback: F) -> FswResult<FswSession>
    where F: Fn(Vec<FswEvent>) + 'static
  {
    let session = self.build()?;
    session.set_callback(callback)?;
    Ok(session)
  }

  /// Add a path to monitor for this session.
  pub fn add_path<P>(mut self, path: P) -> Self
    where P: AsRef<Path>
  {
    self.paths.push(path.as_ref().to_owned());
    self
  }

  /// Set the type of monitor for this session.
  pub fn monitor(mut self, monitor: FswMonitorType) -> Self {
    self.monitor_type = monitor;
    self
  }

  /// Add a custom property to this session. Properties with the same name will keep the last value
  /// specified.
  pub fn property(mut self, name: &str, value: &str) -> Self {
    self.properties.insert(name.to_owned(), value.to_owned());
    self
  }

  /// Set the overflow property for this session.
  pub fn overflow(mut self, overflow: Option<bool>) -> Self {
    self.overflow = overflow;
    self
  }

  /// Set the latency for this session, for monitors using this property.
  pub fn latency(mut self, latency: Option<c_double>) -> Self {
    self.latency = latency;
    self
  }

  /// Set whether this session should be recursive.
  pub fn recursive(mut self, recursive: Option<bool>) -> Self {
    self.recursive = recursive;
    self
  }

  /// Set whether this session is directory only.
  pub fn directory_only(mut self, directory_only: Option<bool>) -> Self {
    self.directory_only = directory_only;
    self
  }

  /// Set whether this session should follow symlinks.
  pub fn follow_symlinks(mut self, follow_symlinks: Option<bool>) -> Self {
    self.follow_symlinks = follow_symlinks;
    self
  }

  /// Add an event flag filter for this session.
  pub fn add_event_filter(mut self, filter_type: FswEventFlag) -> Self {
    self.event_type_filters.push(filter_type);
    self
  }

  /// Add a filter for this session.
  pub fn add_filter(mut self, filter: FswMonitorFilter) -> Self {
    self.filters.push(filter);
    self
  }
}

/// A session in fswatch, revolving around a handle.
///
/// Calling [`new`](#method.new) creates a new handle, initiating a new session. Options can be set
/// before calling [`start_monitor`](#method.start_monitor).
pub struct FswSession {
  #[cfg(feature = "fswatch_1_10_0")]
  handle: Unique<ffi::FSW_SESSION>,
  #[cfg(not(feature = "fswatch_1_10_0"))]
  handle: ffi::FSW_HANDLE,
  callback_set: AtomicBool,
  path_added: AtomicBool,
  started: AtomicBool
}

impl FswSession {
  /// Create a new session and handle, using the given monitor type.
  pub fn new(monitor_type: FswMonitorType) -> FswResult<FswSession> {
    let handle = unsafe { ffi::fsw_init_session(monitor_type.into()) };
    if handle == ffi::FSW_INVALID_HANDLE {
      return Err(FswError::FromFsw(FswStatus::UnknownError));
    }
    let struct_handle = {
      #[cfg(feature = "fswatch_1_10_0")]
      { unsafe { Unique::new(handle) } }
      #[cfg(not(feature = "fswatch_1_10_0"))]
      { handle }
    };
    Ok(FswSession {
      handle: struct_handle,
      callback_set: AtomicBool::new(false),
      path_added: AtomicBool::new(false),
      started: AtomicBool::new(false)
    })
  }

  fn handle(&self) -> ffi::FSW_HANDLE {
    #[cfg(feature = "fswatch_1_10_0")]
    { *self.handle }
    #[cfg(not(feature = "fswatch_1_10_0"))]
    { self.handle }
  }

  /// Create a new session and handle, using the system default monitor type.
  ///
  /// This is a convenience method for `FswSession::new(FswMonitorType::SystemDefaultMonitorType)`.
  pub fn default() -> FswResult<FswSession> {
    FswSession::new(FswMonitorType::SystemDefault)
  }

  /// Create a new empty [`FswSessionBuilder`](struct.FswSessionBuilder.html).
  ///
  /// This is a convenience method for
  /// [`FswSessionBuilder::empty()`](struct.FswSessionBuilder.html#method.empty).
  pub fn builder() -> FswSessionBuilder {
    FswSessionBuilder::empty()
  }

  /// Create a new [`FswSessionBuilder`](struct.FswSessionBuilder.html) with the given paths.
  ///
  /// This is a convenience method for
  /// [`FswSessionBuilder::new(paths)`](struct.FswSessionBuilder.html#method.new).
  pub fn builder_paths<P>(paths: Vec<P>) -> FswSessionBuilder
    where P: AsRef<Path>
  {
    FswSessionBuilder::new(paths)
  }

  fn map_result<T>(ret: T, result: ffi::FSW_STATUS) -> Result<T, FswError> {
    let result: FswStatus = result.into();
    match result {
      FswStatus::Ok => Ok(ret),
      _ => Err(FswError::FromFsw(result))
    }
  }

  /// Add a path to watch for this session.
  pub fn add_path<T: AsRef<Path>>(&self, path: T) -> FswResult<()> {
    let path = path.as_ref().to_string_lossy().into_owned();
    let c_path = CString::new(path).map_err(FswError::NulError)?;
    let result = unsafe { ffi::fsw_add_path(self.handle(), c_path.as_ptr()) };
    let res = FswSession::map_result((), result);
    if res.is_ok() {
      self.path_added.store(true, Ordering::Relaxed);
    }
    res
  }

  /// Add a custom property to this session.
  pub fn add_property(&self, name: &str, value: &str) -> FswResult<()> {
    let c_name = CString::new(name).map_err(FswError::NulError)?;
    let c_value = CString::new(value).map_err(FswError::NulError)?;
    let result = unsafe { ffi::fsw_add_property(self.handle(), c_name.as_ptr(), c_value.as_ptr()) };
    FswSession::map_result((), result)
  }

  /// Set whether to allow overflow for this session.
  pub fn set_allow_overflow(&self, allow_overflow: bool) -> FswResult<()> {
    let result = unsafe { ffi::fsw_set_allow_overflow(self.handle(), allow_overflow) };
    FswSession::map_result((), result)
  }

  extern fn callback_wrapper(events: *const ffi::fsw_cevent, event_num: c_uint, data: *mut c_void) {
    let events: &[ffi::fsw_cevent] = unsafe { std::slice::from_raw_parts(events, event_num as usize) };
    let mapped_events = events.iter()
      .map(|x| {
        let path = unsafe { CStr::from_ptr(x.path) }.to_string_lossy().to_string();
        let flags = unsafe { std::slice::from_raw_parts(x.flags, x.flags_num as usize) };
        let flags = flags.iter().map(Into::into).collect();
        let time = {
          #[cfg(feature = "use_time")]
          { time::at(time::Timespec::new(x.evt_time, 0)) }
          #[cfg(not(feature = "use_time"))]
          { x.evt_time }
        };
        FswEvent {
          path: path,
          time: time,
          flags: flags
        }
      })
      .collect();
    let closure: &Box<Fn(Vec<FswEvent>) + 'static> = unsafe { &*(data as *const Box<Fn(Vec<FswEvent>) + 'static>) };
    closure(mapped_events);
  }

  /// Set the callback for this session.
  ///
  /// The callback will receive a `Vec<FswEvent>`, which is a copy of the events given by fswatch.
  ///
  /// # Safety
  ///
  /// Calling this multiple times will cause this session to use the last callback specified, but
  /// due to the limited functions in the C API, the previous callbacks will never be freed from
  /// memory, causing a memory leak.
  pub fn set_callback<F>(&self, callback: F) -> FswResult<()>
    where F: Fn(Vec<FswEvent>) + 'static
  {
    let cb: Box<Box<Fn(Vec<FswEvent>) + 'static>> = Box::new(Box::new(callback));
    let raw = Box::into_raw(cb) as *mut _;
    let result = unsafe { ffi::fsw_set_callback(self.handle(), FswSession::callback_wrapper, raw) };
    let res = FswSession::map_result((), result);
    if res.is_ok() {
      self.callback_set.store(true, Ordering::Relaxed);
    }
    res
  }

  /// Set the latency for this session.
  pub fn set_latency(&self, latency: c_double) -> FswResult<()> {
    let result = unsafe { ffi::fsw_set_latency(self.handle(), latency) };
    FswSession::map_result((), result)
  }

  /// Set whether this session should be recursive.
  pub fn set_recursive(&self, recursive: bool) -> FswResult<()> {
    let result = unsafe { ffi::fsw_set_recursive(self.handle(), recursive) };
    FswSession::map_result((), result)
  }

  /// Set whether this session should be directory only.
  pub fn set_directory_only(&self, directory_only: bool) -> FswResult<()> {
    let result = unsafe { ffi::fsw_set_directory_only(self.handle(), directory_only) };
    FswSession::map_result((), result)
  }

  /// Set whether this session should follow symlinks.
  pub fn set_follow_symlinks(&self, follow_symlinks: bool) -> FswResult<()> {
    let result = unsafe { ffi::fsw_set_follow_symlinks(self.handle(), follow_symlinks) };
    FswSession::map_result((), result)
  }

  /// Add an event filter for the given event flag.
  pub fn add_event_type_filter(&self, event_type: FswEventFlag) -> FswResult<()> {
    let filter = ffi::fsw_event_type_filter {
      flag: event_type.into()
    };
    let result = unsafe { ffi::fsw_add_event_type_filter(self.handle(), filter) };
    FswSession::map_result((), result)
  }

  /// Add a filter.
  pub fn add_filter(&self, filter: FswMonitorFilter) -> FswResult<()> {
    let c_text = CString::new(filter.text).map_err(FswError::NulError)?;
    let c_filter = ffi::fsw_cmonitor_filter {
      text: c_text.as_ptr(),
      filter_type: filter.filter_type.into(),
      case_sensitive: filter.case_sensitive,
      extended: filter.extended
    };
    let result = unsafe { ffi::fsw_add_filter(self.handle(), c_filter) };
    FswSession::map_result((), result)
  }

  /// Start monitoring for this session.
  ///
  /// Depending on the monitor you are using, this method may block.
  ///
  /// # Errors
  ///
  /// This method will return an error if [`set_callback`](#method.set_callback) has not been
  /// successfully called or if [`add_path`](#method.add_path) has not been successfully called at
  /// least once. To start the monitor without these checks, use
  /// [`start_monitor_unchecked`](#method.start_monitor_unchecked).
  pub fn start_monitor(&self) -> FswResult<()> {
    if !self.callback_set.load(Ordering::Relaxed) || !self.path_added.load(Ordering::Relaxed) {
      return Err(FswError::MissingRequiredParameters);
    }
    self._start_monitor()
  }

  /// Start monitoring for this session.
  ///
  /// Depending on the monitor you are using, this method may block.
  ///
  /// # Safety
  ///
  /// This function will cause an illegal memory access or another type of memory error, crashing
  /// the program, if it is called without a callback or without any paths. As far as I can tell,
  /// this is a problem in the C API of libfswatch.
  pub unsafe fn start_monitor_unchecked(&self) -> FswResult<()> {
    self._start_monitor()
  }

  fn _start_monitor(&self) -> FswResult<()> {
    let result = unsafe { ffi::fsw_start_monitor(self.handle()) };
    let res = FswSession::map_result((), result);
    if res.is_ok() {
      self.started.store(true, Ordering::Relaxed);
    }
    res
  }

  /// Destroy this session, freeing it from memory and invalidating its handle.
  ///
  /// This is called automatically when the session goes out of scope.
  #[cfg(feature = "fswatch_1_10_0")]
  pub fn destroy_session(&self) -> FswResult<()> {
    if self.started.load(Ordering::Relaxed) {
      let result = unsafe { ffi::fsw_destroy_session(self.handle()) };
      FswSession::map_result((), result)
    } else {
      Ok(())
    }
  }
  /// Destroy this session, freeing it from memory and invalidating its handle.
  ///
  /// This is called automatically when the session goes out of scope.
  #[cfg(not(feature = "fswatch_1_10_0"))]
  pub fn destroy_session(&self) -> FswResult<()> {
    let result = unsafe { ffi::fsw_destroy_session(self.handle()) };
    FswSession::map_result((), result)
  }

  /// Stop the monitor for this session, unblocking `start_monitor` calls.
  #[cfg(feature = "fswatch_1_10_0")]
  pub fn stop_monitor(&self) -> FswResult<()> {
    let result = unsafe { ffi::fsw_stop_monitor(self.handle()) };
    FswSession::map_result((), result)
  }

  pub fn iter(&self) -> FswSessionIterator {
    let cloned_handle = {
      #[cfg(feature = "fswatch_1_10_0")]
      unsafe { Unique::new(*self.handle) }
      #[cfg(not(feature = "fswatch_1_10_0"))]
      { self.handle }
    };
    let cloned = FswSession {
      handle: cloned_handle,
      callback_set: AtomicBool::new(self.callback_set.load(Ordering::Relaxed)),
      path_added: AtomicBool::new(self.path_added.load(Ordering::Relaxed)),
      started: AtomicBool::new(self.started.load(Ordering::Relaxed))
    };
    cloned.into_iter()
  }
}

impl IntoIterator for FswSession {
  type Item = (Arc<FswSession>, FswEvent);
  type IntoIter = FswSessionIterator;

  fn into_iter(self) -> Self::IntoIter {
    FswSessionIterator::assume_new(self)
  }
}

impl Drop for FswSession {
  fn drop(&mut self) {
    // We ignore the status of destroying this session, as it can be manually destroyed before being
    // dropped. Even if it couldn't, nothing could be done at this point.
    let _ = self.destroy_session();
  }
}

/// An iterator over the events reported by a [`FswSession`](struct.FswSession.html).
///
/// This will spawn a new thread and call
/// [`start_monitor`](struct.FswSession.html#method.start_monitor) on the
/// [`FswSession`](struct.FswSession.html) when [`next`](#method.next) is called for the first time.
/// The iterator will block until the session receives a new event, which is immediately passed on
/// to a channel to the main thread and returned from the `next` method.
///
/// # Panics
///
/// This iterator will start a panic if the `FswSession` it represents does not have at least one
/// path added to it. This is because the result of `start_monitor` is unwrapped when `next` is
/// called for the first time.
///
/// # Safety
///
/// This iterator sets a callback on the `FswSession` it represents, so in order to prevent memory
/// leaks (see [`set_callback`](struct.FswSession.html#method.set_callback)), only use this iterator
/// on sessions without callbacks previously set.
pub struct FswSessionIterator {
  session: Arc<FswSession>,
  rx: Receiver<FswEvent>,
  started: bool,
  stopped: Arc<AtomicBool>
}

impl FswSessionIterator {
  pub fn new(session: FswSession) -> FswResult<Self> {
    let (tx, rx) = channel();
    FswSessionIterator::adapt_session(&session, tx)?;
    Ok(FswSessionIterator::create(session, rx))
  }

  /// Returns a reference to the interal FswSession the iterator was created from.
  ///
  /// This simply calls `self.session.clone()`, where `self.session` is an `Arc<FswSession>`.
  pub fn session(&self) -> Arc<FswSession> {
    self.session.clone()
  }

  fn assume_new(session: FswSession) -> Self {
    let (tx, rx) = channel();
    let _ = FswSessionIterator::adapt_session(&session, tx);
    FswSessionIterator::create(session, rx)
  }

  fn create(session: FswSession, rx: Receiver<FswEvent>) -> Self {
    FswSessionIterator {
      session: Arc::new(session),
      rx: rx,
      started: false,
      stopped: Arc::new(AtomicBool::new(false))
    }
  }

  fn adapt_session(session: &FswSession, tx: Sender<FswEvent>) -> FswResult<()> {
    session.set_callback(move |events| {
      for event in events {
        tx.send(event).unwrap();
      }
    })
  }

  fn start(&mut self) {
    self.started = true;
    let thread_session = self.session();
    let thread_stopped = self.stopped.clone();
    std::thread::spawn(move || {
      thread_session.start_monitor().unwrap();
      thread_stopped.store(true, Ordering::Relaxed);
    });
  }
}

impl Iterator for FswSessionIterator {
  type Item = (Arc<FswSession>, FswEvent);

  fn next(&mut self) -> Option<Self::Item> {
    if !self.started {
      self.start();
    }
    while !self.stopped.load(Ordering::Relaxed) {
      match self.rx.recv_timeout(std::time::Duration::from_secs(1)) {
        Ok(e) => return Some((self.session(), e)),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {},
        Err(_) => return None
      }
    }
    None
  }
}
