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

use std::fmt;
use std::sync::mpsc::{self, SendError};
use std::thread;

extern crate lazy_static;
extern crate regex;

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
pub enum FilterLevel {
    Trace = 0x01,
    Debug = 0x02,
    Info = 0x04,
    Warning = 0x08,
    Error = 0x10,
    Fatal = 0x20,
}

/// Tuple struct containing log message and its log level
pub struct MsgTuple {
    pub level: FilterLevel,
    pub fn_name: String,
    pub line: u32,
    pub msg: String,
}

#[derive(Debug, Copy, Clone)]
pub enum OutputType {
    Neither = 0x0,
    Console = 0x1,
    File = 0x2,
    Both = 0x3,
}

pub enum Command {
    LogMsg(MsgTuple),
    SetFilterLevel(FilterLevel),
    SetOutput(OutputType),
}

#[derive(Clone, Debug)]
pub struct MtLogger {
    enabled: bool,
    sender: Sender,
}

pub static INSTANCE: OnceCell<MtLogger> = OnceCell::new();


///////////////////////////////////////////////////////////////////////////////
//  Object Implementation
///////////////////////////////////////////////////////////////////////////////

impl MtLogger {
    /// Fully-qualified constructor
    pub fn new(filter: FilterLevel, output_type: OutputType) -> Self {
        let logger_instance = Self::default();

        logger_instance
            .log_cmd(Command::SetOutput(output_type))
            .unwrap();
        logger_instance
            .log_cmd(Command::SetFilterLevel(filter))
            .unwrap();

        logger_instance
    }

    pub fn new_disabled() -> Self {
        // Create dummy channel handles
        let (dummy_tx, _dummy_rx) = mpsc::sync_channel::<Command>(CHANNEL_SIZE);

        // Initialize dummy sender struct
        let dummy_sender = Sender::new(dummy_tx);

        Self {
            enabled: false,
            sender: dummy_sender,
        }
    }

    pub fn global() -> &'static Self {
        INSTANCE.get().expect("Logger not initialized")
    }

    /*  *  *  *  *  *  *  *\
     *  Utility Methods   *
    \*  *  *  *  *  *  *  */

    //FEAT: Bring filtering back to the sending-side
    pub fn log_msg(
        &self,
        level: FilterLevel,
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
 *      MtLogger      *
\*  *  *  *  *  *  *  */
impl Default for MtLogger {
    fn default() -> Self {
        // Create the log messaging and control channel
        let (logger_tx, logger_rx) = mpsc::sync_channel::<Command>(CHANNEL_SIZE);

        //OPT: *PERFORMANCE* Would be better to set the receiver thread's priority as low as possible
        // Initialize receiver struct, build and spawn thread
        let mut log_receiver = Receiver::new(logger_rx, FilterLevel::Info, OutputType::Both);
        thread::Builder::new()
            .name("log_receiver".to_string())
            .spawn(move || log_receiver.main())
            .unwrap();

        // Initialize sender struct
        let log_sender = Sender::new(logger_tx);

        Self {
            enabled: true,
            sender: log_sender,
        }
    }
}


/*  *  *  *  *  *  *  *\
 *     FilterLevel    *
\*  *  *  *  *  *  *  */
impl fmt::Display for FilterLevel {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            FilterLevel::Trace => write!(f, "TRACE"),
            FilterLevel::Debug => write!(f, "DEBUG"),
            FilterLevel::Info => write!(f, "INFO"),
            FilterLevel::Warning => write!(f, "WARNING"),
            FilterLevel::Error => write!(f, "ERROR"),
            FilterLevel::Fatal => write!(f, "FATAL"),
        }
    }
}


///////////////////////////////////////////////////////////////////////////////
//  Macro Definitions
///////////////////////////////////////////////////////////////////////////////

//OPT: *PERFORMANCE* Are the string type conversions expensive?
//TODO: Rename
#[macro_export]
macro_rules! ci_log {
    ($log_level:expr, $( $fmt_args:expr ),*) => {
        let fn_name = {
            fn f() {}
            fn type_name_of<T>(_: T) -> &'static str {
                std::any::type_name::<T>()
            }
            let name = type_name_of(f);
            &name[..name.len() - 3]
        };

        let msg_content: String = format!($( $fmt_args ),*);

        $crate::MtLogger::global().log_msg($log_level, fn_name.to_string(), line!(), msg_content).unwrap();
    };
}

//TODO: Add macros for setting output, filter


///////////////////////////////////////////////////////////////////////////////
//  Unit Tests
///////////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::fmt;
    use std::fs;
    use std::io::Read;
    use std::sync::Mutex;
    use std::thread;
    use std::time;

    use lazy_static::lazy_static;
    use regex::Regex;

    use crate::receiver::{FILE_OUT_FILENAME, STDOUT_FILENAME};
    use crate::{Command, FilterLevel, MtLogger, OutputType, INSTANCE};


    type TestResult = Result<(), Box<dyn Error>>;

    #[derive(Debug, PartialEq)]
    struct GenericError {}
    impl Error for GenericError {}
    impl fmt::Display for GenericError {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "{:?}", self)
        }
    }

    lazy_static! {
        static ref LOGGER_MUTEX: Mutex<()> = Mutex::new(());
    }

    #[derive(Debug, PartialEq)]
    enum VerfFile {
        StdOut,
        FileOut,
    }

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
                    "{:?} header line {} '{}' did not match Regex:\n   {}",
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
                    "Wrong color '{}' on line '{}', should be '{}'",
                    &header_captures[STDOUT_COLOR_IDX], header_line, VERF_MATRIX[i][COLOR_VERF_IDX]
                );
            }
            if &header_captures[padded_level_hdr_capture_idx]
                != VERF_MATRIX[i][PADDED_LEVEL_VERF_IDX]
            {
                panic!(
                    "Wrong padded level '{}' on line '{}', should be '{}'",
                    &header_captures[padded_level_hdr_capture_idx],
                    header_line,
                    VERF_MATRIX[i][PADDED_LEVEL_VERF_IDX]
                );
            }
            if &header_captures[fn_name_hdr_capture_idx] != FN_NAME {
                panic!(
                    "Wrong function name '{}' on line '{}', should be '{}'",
                    &header_captures[fn_name_hdr_capture_idx], header_line, FN_NAME
                );
            }
            if header_captures[line_num_hdr_capture_idx].parse::<u32>()?
                != first_line_num + i as u32
            {
                panic!(
                    "Wrong line number '{}' on line '{}', should be '{}'",
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
                    "{:?} content line {} '{}' did not match content Regex:\n   {}",
                    verf_type,
                    i,
                    content_line,
                    content_regex.as_str()
                )
            });

            if &content_captures[level_content_capture_idx] != VERF_MATRIX[i][LEVEL_VERF_IDX] {
                panic!(
                    "Wrong level '{}' in content line '{}', should be '{}'",
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
        // Acquire logger mutex, will be released once the test function completes
        let _mutex = LOGGER_MUTEX.lock()?;

        // Create or update a logger instance that will log all messages to Both outputs
        let logger = MtLogger::new(FilterLevel::Trace, OutputType::Both);
        INSTANCE.set(logger).or_else(|_| {
            MtLogger::global().log_cmd(Command::SetOutput(OutputType::Both))?;
            MtLogger::global().log_cmd(Command::SetFilterLevel(FilterLevel::Trace))
        })?;

        let first_line_num = line!() + 1;
        ci_log!(FilterLevel::Trace, "This is a TRACE message.");
        ci_log!(FilterLevel::Debug, "This is a DEBUG message.");
        ci_log!(FilterLevel::Info, "This is an INFO message.");
        ci_log!(FilterLevel::Warning, "This is a WARNING message.");
        ci_log!(FilterLevel::Error, "This is an ERROR message.");
        ci_log!(FilterLevel::Fatal, "This is a FATAL message.");

        // Sleep for 1 second to allow the receiver thread to do stuff
        println!("Sleeping for 1s...");
        thread::sleep(time::Duration::from_secs(1));
        println!("Done sleeping!");

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
                    "{:?} header line {} '{}' did not match Regex:\n   {}",
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
                    "Wrong level '{}' on line '{}', should be '{}'",
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
                    "Content line {} '{}' did not match content Regex",
                    i, content_line
                )
            });

            if &content_captures[output_type_capture_idx]
                != VERF_MATRIX[verf_type_idx][i][OUTPUT_TYPE_VERF_IDX]
            {
                panic!(
                    "Wrong output type '{}' on line '{}', should be '{}'",
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
        // Acquire logger mutex, will be released once the test function completes
        let _mutex = LOGGER_MUTEX.lock()?;

        // Create or update a logger instance that will log messages to BOTH outputs
        let logger = MtLogger::new(FilterLevel::Trace, OutputType::Both);
        INSTANCE.set(logger).or_else(|_| {
            MtLogger::global().log_cmd(Command::SetOutput(OutputType::Both))?;
            MtLogger::global().log_cmd(Command::SetFilterLevel(FilterLevel::Trace))
        })?;

        ci_log!(FilterLevel::Trace, "This message appears in BOTH.");
        ci_log!(FilterLevel::Fatal, "This message appears in BOTH.");

        // Log messages to CONSOLE only
        MtLogger::global().log_cmd(Command::SetOutput(OutputType::Console))?;
        ci_log!(FilterLevel::Trace, "This message appears in STDOUT.");
        ci_log!(FilterLevel::Fatal, "This message appears in STDOUT.");

        // Log messages to FILE only
        MtLogger::global().log_cmd(Command::SetOutput(OutputType::File))?;
        ci_log!(FilterLevel::Trace, "This message appears in FILEOUT.");
        ci_log!(FilterLevel::Fatal, "This message appears in FILEOUT.");

        // Log messages to NEITHER output
        MtLogger::global().log_cmd(Command::SetOutput(OutputType::Neither))?;
        ci_log!(FilterLevel::Trace, "This message appears in NEITHER.");
        ci_log!(FilterLevel::Fatal, "This message appears in NEITHER.");

        // Sleep for 1 seconds to allow the receiver thread to do stuff
        println!("Sleeping for 1s...");
        thread::sleep(time::Duration::from_secs(1));
        println!("Done sleeping!");

        // Verify that the verification files contain only the correct messages
        output_type_helper(VerfFile::StdOut)?;
        output_type_helper(VerfFile::FileOut)?;

        Ok(())
    }
}
