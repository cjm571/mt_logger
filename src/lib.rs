/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *\
Filename : logger/mod.rs

Copyright (C) 2020 CJ McAllister
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
    This module will provide data structures and functions that provide
    1st-party logging functionality for game events.

!!!USAGE NOTE!!!
    This module is meant to be created once in a top level, and then cloned
    in each submodule's constructors from a reference to the original.

    Due to the nature of Rusts' "multiple producer, single consumer" model
    of inter-thread communication, all clones will send their messages to
    the single receiver spawned by the original Instance.

\* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

use std::sync::mpsc::{self, SendError};
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

pub mod log_sender;
use self::log_sender::LogSender;
pub mod log_receiver;
use self::log_receiver::LogReceiver;

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
pub struct Instance {
    enabled: bool,
    sender: LogSender,
}

pub static INSTANCE: OnceCell<Instance> = OnceCell::new();

///////////////////////////////////////////////////////////////////////////////
//  Object Implementation
///////////////////////////////////////////////////////////////////////////////

impl Instance {
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
        let dummy_sender = LogSender::new(dummy_tx);

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
 *      Instance      *
\*  *  *  *  *  *  *  */
impl Default for Instance {
    fn default() -> Self {
        // Create the log messaging and control channel
        let (logger_tx, logger_rx) = mpsc::sync_channel::<Command>(CHANNEL_SIZE);

        //OPT: *PERFORMANCE* Would be better to set the receiver thread's priority as low as possible
        // Initialize receiver struct, build and spawn thread
        let mut log_receiver = LogReceiver::new(logger_rx, FilterLevel::Info, OutputType::Both);
        thread::Builder::new()
            .name("log_receiver".to_owned())
            .spawn(move || log_receiver.main())
            .unwrap();

        // Initialize sender struct
        let log_sender = LogSender::new(logger_tx);

        Self {
            enabled: true,
            sender: log_sender,
        }
    }
}

/*  *  *  *  *  *  *  *\
 *     FilterLevel    *
\*  *  *  *  *  *  *  */
impl From<FilterLevel> for String {
    fn from(src: FilterLevel) -> Self {
        match src {
            FilterLevel::Trace => "TRACE".to_owned(),
            FilterLevel::Debug => "DEBUG".to_owned(),
            FilterLevel::Info => "INFO".to_owned(),
            FilterLevel::Warning => "WARNING".to_owned(),
            FilterLevel::Error => "ERROR".to_owned(),
            FilterLevel::Fatal => "FATAL".to_owned(),
        }
    }
}

///////////////////////////////////////////////////////////////////////////////
//  Macro Definitions
///////////////////////////////////////////////////////////////////////////////

//OPT: *PERFORMANCE* Are the string type conversions expensive?
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

        $crate::Instance::global().log_msg($log_level, fn_name.to_owned(), line!(), msg_content).unwrap();
    };
}

///////////////////////////////////////////////////////////////////////////////
//  Unit Tests
///////////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use std::{error::Error, fmt, thread, time};

    use crate::{Command, FilterLevel, Instance, OutputType, INSTANCE};

    type TestResult = Result<(), Box<dyn Error>>;

    #[derive(Debug, PartialEq)]
    struct GenericError {}
    impl Error for GenericError {}
    impl fmt::Display for GenericError {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "{:?}", self)
        }
    }

    #[test]
    fn visual_verification() -> TestResult {
        // Create or update a logger instance that will log all messages to Both outputs
        let logger = Instance::new(FilterLevel::Trace, OutputType::Both);
        INSTANCE.set(logger).or_else(|_| {
            Instance::global().log_cmd(Command::SetOutput(OutputType::Both))?;
            Instance::global().log_cmd(Command::SetFilterLevel(FilterLevel::Trace))
        })?;

        ci_log!(FilterLevel::Trace, "This is a TRACE message.");
        ci_log!(FilterLevel::Debug, "This is a DEBUG message.");
        ci_log!(FilterLevel::Info, "This is an INFO message.");
        ci_log!(FilterLevel::Warning, "This is a WARNING message.");
        ci_log!(FilterLevel::Error, "This is an ERROR message.");
        ci_log!(FilterLevel::Fatal, "This is a FATAL message.");

        // Sleep for 5 seconds to allow the receiver thread to do stuff
        println!("Sleeping for 5s...");
        thread::sleep(time::Duration::from_secs(5));
        println!("Done sleeping!");

        Ok(())
    }

    #[test]
    fn output_type_cmd_test() -> TestResult {
        // Create or update a logger instance that will log messages to BOTH outputs
        let logger = Instance::new(FilterLevel::Trace, OutputType::Both);
        INSTANCE.set(logger).or_else(|_| {
            Instance::global().log_cmd(Command::SetOutput(OutputType::Both))?;
            Instance::global().log_cmd(Command::SetFilterLevel(FilterLevel::Trace))
        })?;

        ci_log!(
            FilterLevel::Trace,
            "This message appears in BOTH console and file."
        );
        ci_log!(
            FilterLevel::Fatal,
            "This message appears in BOTH console and file."
        );

        // Log messages to CONSOLE only
        Instance::global()
            .log_cmd(Command::SetOutput(OutputType::Console))
            .unwrap();
        ci_log!(FilterLevel::Trace, "This message appears in CONSOLE ONLY.");
        ci_log!(FilterLevel::Fatal, "This message appears in CONSOLE ONLY.");

        // Log messages to FILE only
        Instance::global()
            .log_cmd(Command::SetOutput(OutputType::File))
            .unwrap();
        ci_log!(FilterLevel::Trace, "This message appears in FILE ONLY.");
        ci_log!(FilterLevel::Fatal, "This message appears in FILE ONLY.");

        // Log messages to NEITHER output
        Instance::global()
            .log_cmd(Command::SetOutput(OutputType::Neither))
            .unwrap();
        ci_log!(FilterLevel::Trace, "This message appears in FILE ONLY.");
        ci_log!(FilterLevel::Fatal, "This message appears in FILE ONLY.");

        // Log messages to NEITHER output
        Instance::global()
            .log_cmd(Command::SetOutput(OutputType::Neither))
            .unwrap();
        ci_log!(FilterLevel::Trace, "This message appears in FILE ONLY.");
        ci_log!(FilterLevel::Fatal, "This message appears in FILE ONLY.");

        // Log messages to NEITHER output
        Instance::global()
            .log_cmd(Command::SetOutput(OutputType::Neither))
            .unwrap();
        ci_log!(FilterLevel::Trace, "This message appears in FILE ONLY.");
        ci_log!(FilterLevel::Fatal, "This message appears in FILE ONLY.");

        // Log messages to NEITHER output
        Instance::global()
            .log_cmd(Command::SetOutput(OutputType::Neither))
            .unwrap();
        ci_log!(FilterLevel::Trace, "This message appears in FILE ONLY.");
        ci_log!(FilterLevel::Fatal, "This message appears in FILE ONLY.");

        // Log messages to NEITHER output
        Instance::global()
            .log_cmd(Command::SetOutput(OutputType::Neither))
            .unwrap();
        ci_log!(FilterLevel::Trace, "This message appears in FILE ONLY.");
        ci_log!(FilterLevel::Fatal, "This message appears in FILE ONLY.");

        // Log messages to NEITHER output
        Instance::global()
            .log_cmd(Command::SetOutput(OutputType::Neither))
            .unwrap();
        ci_log!(FilterLevel::Trace, "This message appears in FILE ONLY.");
        ci_log!(FilterLevel::Fatal, "This message appears in FILE ONLY.");

        // Log messages to NEITHER output
        Instance::global()
            .log_cmd(Command::SetOutput(OutputType::Neither))
            .unwrap();
        ci_log!(FilterLevel::Trace, "This message appears in FILE ONLY.");
        ci_log!(FilterLevel::Fatal, "This message appears in FILE ONLY.");

        // Log messages to NEITHER output
        Instance::global()
            .log_cmd(Command::SetOutput(OutputType::Neither))
            .unwrap();
        ci_log!(FilterLevel::Trace, "This message appears in FILE ONLY.");
        ci_log!(FilterLevel::Fatal, "This message appears in FILE ONLY.");

        // Log messages to NEITHER output
        Instance::global()
            .log_cmd(Command::SetOutput(OutputType::Neither))
            .unwrap();
        ci_log!(FilterLevel::Trace, "This message appears in FILE ONLY.");
        ci_log!(FilterLevel::Fatal, "This message appears in FILE ONLY.");

        // Log messages to NEITHER output
        Instance::global()
            .log_cmd(Command::SetOutput(OutputType::Neither))
            .unwrap();
        ci_log!(FilterLevel::Trace, "This message appears in NEITHER ONLY.");
        ci_log!(FilterLevel::Fatal, "This message appears in NEITHER ONLY.");

        // Sleep for 5 seconds to allow the receiver thread to do stuff
        println!("Sleeping for 5s...");
        thread::sleep(time::Duration::from_secs(5));
        println!("Done sleeping!");

        Ok(())
    }
}
