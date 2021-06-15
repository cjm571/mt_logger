/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *\
Filename : lib.rs

Copyright (C) 2021 CJ McAllister
    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software Foundation,
    Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA

Purpose:
    This library provides a multi-threaded, global logger.

    All logging actions occur in the logging thread, leaving the main thread
    free to do all the cool stuff it wants to do!

\* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

use std::error::Error;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, SendError};
use std::sync::Arc;
use std::thread;

use once_cell::sync::OnceCell;


///////////////////////////////////////////////////////////////////////////////
//  Named Constants
///////////////////////////////////////////////////////////////////////////////

// Buffer size of the sync_channel for sending log messages
const CHANNEL_SIZE: usize = 512;


///////////////////////////////////////////////////////////////////////////////
//  Module Declarations
///////////////////////////////////////////////////////////////////////////////

pub mod sender;
use self::sender::Sender;
pub mod receiver;
use self::receiver::Receiver;


///////////////////////////////////////////////////////////////////////////////
//  Data Structures
///////////////////////////////////////////////////////////////////////////////

/// Denotes the level or severity of the log message.
#[derive(Debug, Copy, Clone, PartialEq, PartialOrd)]
pub enum Level {
    Trace = 0x01,
    Debug = 0x02,
    Info = 0x04,
    Warning = 0x08,
    Error = 0x10,
    Fatal = 0x20,
}

/// Tuple struct containing log message and its log level
pub struct MsgTuple {
    pub level: Level,
    pub fn_name: String,
    pub line: u32,
    pub msg: String,
}

#[derive(Debug, Copy, Clone)]
pub enum OutputStream {
    Neither = 0x0,
    StdOut = 0x1,
    File = 0x2,
    Both = 0x3,
}

pub enum Command {
    LogMsg(MsgTuple),
    SetOutputLevel(Level),
    SetOutputStream(OutputStream),
}

#[derive(Clone, Debug)]
pub struct MtLogger {
    enabled: bool,
    sender: Sender,
    msg_count: Arc<AtomicU64>,
}

#[derive(Debug)]
pub enum MtLoggerError {
    LoggerNotInitialized,

    // Wrappers
    SendError(SendError<Command>),
}

// Clippy doesn't realize this is used in the macros...
#[allow(dead_code)]
static INSTANCE: OnceCell<MtLogger> = OnceCell::new();


///////////////////////////////////////////////////////////////////////////////
//  Object Implementation
///////////////////////////////////////////////////////////////////////////////

impl MtLogger {
    /// Fully-qualified constructor
    pub fn new(output_level: Level, output_stream: OutputStream) -> Self {
        // Create the log messaging and control channel
        let (logger_tx, logger_rx) = mpsc::sync_channel::<Command>(CHANNEL_SIZE);

        // Create the shared message count
        let msg_count = Arc::new(AtomicU64::new(0));

        // Initialize receiver struct, build and spawn thread
        let mut log_receiver = Receiver::new(
            logger_rx,
            output_level,
            output_stream,
            Arc::clone(&msg_count),
        );
        thread::Builder::new()
            .name("log_receiver".to_string())
            .spawn(move || log_receiver.main())
            .unwrap();

        // Initialize sender struct
        let log_sender = Sender::new(logger_tx);

        Self {
            enabled: true,
            sender: log_sender,
            msg_count,
        }
    }


    /*  *  *  *  *  *  *  *\
     *  Accessor Methods  *
    \*  *  *  *  *  *  *  */

    pub fn msg_count(&self) -> u64 {
        self.msg_count.load(Ordering::SeqCst)
    }


    /*  *  *  *  *  *  *  *\
     *   Utility Methods  *
    \*  *  *  *  *  *  *  */

    //FEAT: Bring filtering back to the sending-side
    pub fn log_msg(
        &self,
        level: Level,
        fn_name: String,
        line: u32,
        msg: String,
    ) -> Result<(), SendError<Command>> {
        // If logging is enabled, package log message into tuple and send
        if self.enabled {
            let log_tuple = MsgTuple {
                level,
                fn_name,
                line,
                msg,
            };
            self.sender.send_log(Command::LogMsg(log_tuple))
        } else {
            Ok(())
        }
    }

    pub fn log_cmd(&self, cmd: Command) -> Result<(), SendError<Command>> {
        if self.enabled {
            self.sender.send_cmd(cmd)
        } else {
            Ok(())
        }
    }
}


///////////////////////////////////////////////////////////////////////////////
//  Trait Implementations
///////////////////////////////////////////////////////////////////////////////

/*  *  *  *  *  *  *  *\
 *       Level        *
\*  *  *  *  *  *  *  */

impl fmt::Display for Level {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Trace => write!(f, "TRACE"),
            Self::Debug => write!(f, "DEBUG"),
            Self::Info => write!(f, "INFO"),
            Self::Warning => write!(f, "WARNING"),
            Self::Error => write!(f, "ERROR"),
            Self::Fatal => write!(f, "FATAL"),
        }
    }
}


/*  *  *  *  *  *  *  *\
 *    MtLoggerError   *
\*  *  *  *  *  *  *  */

impl Error for MtLoggerError {}

impl fmt::Display for MtLoggerError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::LoggerNotInitialized => {
                write!(
                    f,
                    "Attempted a command before the logger instance was initialized"
                )
            }

            // Wrappers
            Self::SendError(send_err) => {
                write!(
                    f,
                    "Encountered SendError '{}' while performing a logger command",
                    send_err
                )
            }
        }
    }
}

impl From<SendError<Command>> for MtLoggerError {
    fn from(src: SendError<Command>) -> Self {
        Self::SendError(src)
    }
}


///////////////////////////////////////////////////////////////////////////////
//  Macro Definitions
///////////////////////////////////////////////////////////////////////////////

#[macro_export]
macro_rules! mt_new {
    ($output_level:expr, $output_stream:expr) => {{
        let logger = $crate::MtLogger::new($output_level, $output_stream);

        $crate::INSTANCE
            .set(logger)
            .expect("MtLogger INSTANCE already initialized");
    }};
}

#[macro_export]
macro_rules! mt_log {
    ($log_level:expr, $( $fmt_args:expr ),*) => {{
        let fn_name = {
            fn f() {}
            fn type_name_of<T>(_: T) -> &'static str {
                std::any::type_name::<T>()
            }
            let name = type_name_of(f);
            &name[..name.len() - 3]
        };

        let msg_content: String = format!($( $fmt_args ),*);

        $crate::INSTANCE
            .get()
            // If None is encountered, the logger has not been initialized, so do nothing
            .and_then(|instance| instance.log_msg(
                $log_level,
                fn_name.to_string(),
                line!(),
                msg_content)
                .ok()
            );
    }};
}

#[macro_export]
macro_rules! mt_stream {
    ($output_stream:expr) => {{
        // Get the global instance and send a command to set the output stream
        $crate::INSTANCE
            .get()
            // If None is encountered, the logger has not been initialized, so do nothing
            .and_then(|instance| {
                instance
                    .log_cmd($crate::Command::SetOutputStream($output_stream))
                    .ok()
            });
    }};
}

#[macro_export]
macro_rules! mt_level {
    ($output_level:expr) => {{
        // Get the global instance and send a command to set the output level
        $crate::INSTANCE
            .get()
            // If None is encountered, the logger has not been initialized, so do nothing
            .and_then(|instance| {
                instance
                    .log_cmd($crate::Command::SetOutputLevel($output_level))
                    .ok()
            });
    }};
}

#[macro_export]
macro_rules! mt_count {
    () => {{
        // Get the global instance and retrieve the message count
        $crate::INSTANCE
            .get()
            // If None is encountered, the logger has not been initialized, which is an error
            .and_then(|instance| Some(instance.msg_count()))
            .unwrap()
    }};
}


///////////////////////////////////////////////////////////////////////////////
//  Unit Tests
///////////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::fs;
    use std::io::Read;
    use std::sync::Mutex;
    use std::thread;
    use std::time;

    use lazy_static::lazy_static;
    use regex::Regex;

    use crate::receiver::{FILE_OUT_FILENAME, STDOUT_FILENAME};
    use crate::{Level, MtLogger, OutputStream, INSTANCE};


    type TestResult = Result<(), Box<dyn Error>>;


    lazy_static! {
        static ref LOGGER_MUTEX: Mutex<()> = Mutex::new(());
    }

    #[derive(Debug, PartialEq)]
    enum VerfFile {
        StdOut,
        FileOut,
    }

    const SLEEP_INTERVAL_MS: u64 = 10;

    const STDOUT_HDR_REGEX_STR: &str = r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}.\d{3}: \x1b\[(\d{3};\d{3}m)\[(\s*(\w*)\s*)\]\x1b\[0m (.*)\(\) line (\d*):";
    const STDOUT_COLOR_IDX: usize = 1;
    const STDOUT_PADDED_LEVEL_IDX: usize = 2;
    const STDOUT_PADLESS_LEVEL_IDX: usize = 3;
    const STDOUT_FN_NAME_IDX: usize = 4;
    const STDOUT_LINE_NUM_IDX: usize = 5;

    const FILE_OUT_HDR_REGEX_STR: &str =
        r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}.\d{3}: \[(\s*(\w*)\s*)\] (.*)\(\) line (\d*):";
    const FILE_OUT_PADDED_LEVEL_IDX: usize = 1;
    const FILE_OUT_PADLESS_LEVEL_IDX: usize = 2;
    const FILE_OUT_FN_NAME_IDX: usize = 3;
    const FILE_OUT_LINE_NUM_IDX: usize = 4;


    fn format_verf_helper(verf_type: VerfFile, first_line_num: u32) -> TestResult {
        // Set up the verification items
        const FN_NAME: &str = "mt_logger::tests::format_verification";
        const VERF_MATRIX: [[&str; 3]; 6] = [
            ["TRACE", "030;105m", "  TRACE  "],
            ["DEBUG", "030;106m", "  DEBUG  "],
            ["INFO", "030;107m", "  INFO   "],
            ["WARNING", "030;103m", " WARNING "],
            ["ERROR", "030;101m", "  ERROR  "],
            ["FATAL", "031;040m", "  FATAL  "],
        ];
        const LEVEL_VERF_IDX: usize = 0;
        const COLOR_VERF_IDX: usize = 1;
        const PADDED_LEVEL_VERF_IDX: usize = 2;

        // Set up output-specific parameters
        let filepath;
        let padded_level_hdr_capture_idx;
        let fn_name_hdr_capture_idx;
        let line_num_hdr_capture_idx;
        let header_regex;
        match verf_type {
            VerfFile::StdOut => {
                filepath = STDOUT_FILENAME;
                padded_level_hdr_capture_idx = STDOUT_PADDED_LEVEL_IDX;
                fn_name_hdr_capture_idx = STDOUT_FN_NAME_IDX;
                line_num_hdr_capture_idx = STDOUT_LINE_NUM_IDX;
                header_regex = Regex::new(STDOUT_HDR_REGEX_STR)?;
            }
            VerfFile::FileOut => {
                filepath = FILE_OUT_FILENAME;
                padded_level_hdr_capture_idx = FILE_OUT_PADDED_LEVEL_IDX;
                fn_name_hdr_capture_idx = FILE_OUT_FN_NAME_IDX;
                line_num_hdr_capture_idx = FILE_OUT_LINE_NUM_IDX;
                header_regex = Regex::new(FILE_OUT_HDR_REGEX_STR)?;
            }
        }
        let level_content_capture_idx = 1;

        // Create regex for message content
        let content_regex = Regex::new(r"^   This is an? (\w*) message.")?;

        // Open verification file and read into vector by lines
        let mut verf_file = fs::OpenOptions::new().read(true).open(filepath)?;
        let mut verf_string = String::new();
        verf_file.read_to_string(&mut verf_string)?;

        let mut verf_lines: Vec<&str> = verf_string.split('\n').collect();
        let mut verf_line_iter = verf_lines.iter_mut();

        // Iterate over lines, verifying along the way
        let mut i = 0;
        while let Some(header_line) = verf_line_iter.next().filter(|v| !v.is_empty()) {
            // Match regex against header line, and capture groups
            let header_captures = header_regex.captures(header_line).unwrap_or_else(|| {
                panic!(
                    "{:?}: Header line {} '{}' did not match Regex:\n   {}",
                    verf_type,
                    i,
                    header_line,
                    header_regex.as_str()
                )
            });

            // Verify capture groups
            if verf_type == VerfFile::StdOut
                && &header_captures[STDOUT_COLOR_IDX] != VERF_MATRIX[i][COLOR_VERF_IDX]
            {
                panic!(
                    "{:?}: Wrong color '{}' on line '{}', should be '{}'",
                    verf_type,
                    &header_captures[STDOUT_COLOR_IDX],
                    header_line,
                    VERF_MATRIX[i][COLOR_VERF_IDX]
                );
            }
            if &header_captures[padded_level_hdr_capture_idx]
                != VERF_MATRIX[i][PADDED_LEVEL_VERF_IDX]
            {
                panic!(
                    "{:?}: Wrong padded level '{}' on line '{}', should be '{}'",
                    verf_type,
                    &header_captures[padded_level_hdr_capture_idx],
                    header_line,
                    VERF_MATRIX[i][PADDED_LEVEL_VERF_IDX]
                );
            }
            if &header_captures[fn_name_hdr_capture_idx] != FN_NAME {
                panic!(
                    "{:?}: Wrong function name '{}' on line '{}', should be '{}'",
                    verf_type, &header_captures[fn_name_hdr_capture_idx], header_line, FN_NAME
                );
            }
            if header_captures[line_num_hdr_capture_idx].parse::<u32>()?
                != first_line_num + i as u32
            {
                panic!(
                    "{:?}: Wrong line number '{}' on line '{}', should be '{}'",
                    verf_type,
                    &header_captures[line_num_hdr_capture_idx],
                    header_line,
                    first_line_num + i as u32
                );
            }

            // Verify content line
            let content_line = verf_line_iter
                .next()
                .unwrap_or_else(|| panic!("Missing content line after header '{}'", header_line));
            let content_captures = content_regex.captures(content_line).unwrap_or_else(|| {
                panic!(
                    "{:?}: Content line {} '{}' did not match content Regex:\n   {}",
                    verf_type,
                    i,
                    content_line,
                    content_regex.as_str()
                )
            });

            if &content_captures[level_content_capture_idx] != VERF_MATRIX[i][LEVEL_VERF_IDX] {
                panic!(
                    "{:?}: Wrong level '{}' in content line '{}', should be '{}'",
                    verf_type,
                    &content_captures[level_content_capture_idx],
                    content_line,
                    VERF_MATRIX[i][LEVEL_VERF_IDX]
                )
            }

            i += 1;
        }

        Ok(())
    }

    #[test]
    fn format_verification() -> TestResult {
        const MSG_COUNT: u64 = 6;

        // Acquire logger mutex, will be released once the test function completes
        let _mutex = LOGGER_MUTEX.lock()?;

        // Create or update a logger instance that will log all messages to Both outputs
        let logger = MtLogger::new(Level::Trace, OutputStream::Both);
        if let Err(_) = INSTANCE.set(logger) {
            mt_stream!(OutputStream::Both);
            mt_level!(Level::Trace);
        }

        let first_line_num = line!() + 1;
        mt_log!(Level::Trace, "This is a TRACE message.");
        mt_log!(Level::Debug, "This is a DEBUG message.");
        mt_log!(Level::Info, "This is an INFO message.");
        mt_log!(Level::Warning, "This is a WARNING message.");
        mt_log!(Level::Error, "This is an ERROR message.");
        mt_log!(Level::Fatal, "This is a FATAL message.");

        // Sleep for to allow the receiver thread to do stuff
        println!("Sleeping until all messages have been received...");
        let start_time = time::Instant::now();
        while mt_count!() < MSG_COUNT {
            thread::sleep(time::Duration::from_millis(SLEEP_INTERVAL_MS));
        }
        println!("Done sleeping after {}ms", start_time.elapsed().as_millis());

        // Verify that the verification files contain well-formatted messages
        format_verf_helper(VerfFile::StdOut, first_line_num)?;
        format_verf_helper(VerfFile::FileOut, first_line_num)?;

        Ok(())
    }

    fn output_type_helper(verf_type: VerfFile) -> TestResult {
        // Set up the verification items
        const VERF_MATRIX: [[[&str; 2]; 4]; 2] = [
            [
                ["TRACE", "BOTH"],
                ["FATAL", "BOTH"],
                ["TRACE", "STDOUT"],
                ["FATAL", "STDOUT"],
            ],
            [
                ["TRACE", "BOTH"],
                ["FATAL", "BOTH"],
                ["TRACE", "FILEOUT"],
                ["FATAL", "FILEOUT"],
            ],
        ];
        const STDOUT_TYPE_IDX: usize = 0;
        const FILE_OUT_TYPE_IDX: usize = 1;
        const LEVEL_VERF_IDX: usize = 0;
        const OUTPUT_TYPE_VERF_IDX: usize = 1;

        // Set up output-specific parameters
        let filepath;
        let verf_type_idx;
        let padless_level_hdr_capture_idx;
        let header_regex;
        match verf_type {
            VerfFile::StdOut => {
                filepath = STDOUT_FILENAME;
                verf_type_idx = STDOUT_TYPE_IDX;
                padless_level_hdr_capture_idx = STDOUT_PADLESS_LEVEL_IDX;
                header_regex = Regex::new(STDOUT_HDR_REGEX_STR)?;
            }
            VerfFile::FileOut => {
                filepath = FILE_OUT_FILENAME;
                verf_type_idx = FILE_OUT_TYPE_IDX;
                padless_level_hdr_capture_idx = FILE_OUT_PADLESS_LEVEL_IDX;
                header_regex = Regex::new(FILE_OUT_HDR_REGEX_STR)?;
            }
        }
        let output_type_capture_idx = 1;

        // Create regex for message content
        let content_regex = Regex::new(r"^\s*This message appears in (\w*).")?;

        // Open verification file and read into vector by lines
        let mut verf_file = fs::OpenOptions::new().read(true).open(filepath)?;
        let mut verf_string = String::new();
        verf_file.read_to_string(&mut verf_string)?;

        let mut verf_lines: Vec<&str> = verf_string.split('\n').collect();
        let mut verf_line_iter = verf_lines.iter_mut();

        // Verify that the verification files contain the correct filter level and content lines
        let mut i = 0;
        while let Some(header_line) = verf_line_iter.next().filter(|v| !v.is_empty()) {
            // Verify header contains the correct log level
            let header_captures = header_regex.captures(header_line).unwrap_or_else(|| {
                panic!(
                    "{:?}: Header line {} '{}' did not match Regex:\n   {}",
                    verf_type,
                    i,
                    header_line,
                    header_regex.as_str()
                )
            });
            if &header_captures[padless_level_hdr_capture_idx]
                != VERF_MATRIX[verf_type_idx][i][LEVEL_VERF_IDX]
            {
                panic!(
                    "{:?}: Wrong level '{}' on line '{}', should be '{}'",
                    verf_type,
                    &header_captures[padless_level_hdr_capture_idx],
                    header_line,
                    VERF_MATRIX[verf_type_idx][i][LEVEL_VERF_IDX]
                );
            }

            // Verify content contains the correct output type
            let content_line = verf_line_iter
                .next()
                .unwrap_or_else(|| panic!("Missing content line after header '{}'", header_line));
            let content_captures = content_regex.captures(content_line).unwrap_or_else(|| {
                panic!(
                    "{:?}: Content line {} '{}' did not match content Regex",
                    verf_type, i, content_line
                )
            });

            if &content_captures[output_type_capture_idx]
                != VERF_MATRIX[verf_type_idx][i][OUTPUT_TYPE_VERF_IDX]
            {
                panic!(
                    "{:?}: Wrong output type '{}' on line '{}', should be '{}'",
                    verf_type,
                    &content_captures[output_type_capture_idx],
                    content_line,
                    VERF_MATRIX[verf_type_idx][i][OUTPUT_TYPE_VERF_IDX]
                )
            }

            i += 1;
        }

        Ok(())
    }

    #[test]
    fn output_type_cmd_test() -> TestResult {
        const MSG_COUNT: u64 = 6;

        // Acquire logger mutex, will be released once the test function completes
        let _mutex = LOGGER_MUTEX.lock()?;

        // Create or update a logger instance that will log all messages to Both outputs
        let logger = MtLogger::new(Level::Trace, OutputStream::Both);
        if let Err(_) = INSTANCE.set(logger) {
            mt_stream!(OutputStream::Both);
            mt_level!(Level::Trace);
        }

        mt_log!(Level::Trace, "This message appears in BOTH.");
        mt_log!(Level::Fatal, "This message appears in BOTH.");

        // Log messages to STDOUT only
        mt_stream!(OutputStream::StdOut);
        mt_log!(Level::Trace, "This message appears in STDOUT.");
        mt_log!(Level::Fatal, "This message appears in STDOUT.");

        // Log messages to FILE only
        mt_stream!(OutputStream::File);
        mt_log!(Level::Trace, "This message appears in FILEOUT.");
        mt_log!(Level::Fatal, "This message appears in FILEOUT.");

        // Log messages to NEITHER output
        mt_stream!(OutputStream::Neither);
        mt_log!(Level::Trace, "This message appears in NEITHER.");
        mt_log!(Level::Fatal, "This message appears in NEITHER.");

        // Sleep to allow the receiver thread to do stuff
        println!("Sleeping until all messages have been received...");
        let start_time = time::Instant::now();
        while mt_count!() < MSG_COUNT {
            thread::sleep(time::Duration::from_millis(SLEEP_INTERVAL_MS));
        }
        println!("Done sleeping after {}ms", start_time.elapsed().as_millis());

        // Verify that the verification files contain only the correct messages
        output_type_helper(VerfFile::StdOut)?;
        output_type_helper(VerfFile::FileOut)?;

        Ok(())
    }
}
