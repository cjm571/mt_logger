/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *\
Filename : logger/log_receiver.rs

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
    This module defines the Log Receiver module, which will exist in its own
    thread, listening for messages on a channel from the Sender.

\* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc};

use std::fs::{self, File};
use std::io::prelude::*;
use std::path::PathBuf;

use chrono::Local;

use crate::{Command, Level, MsgTuple, OutputStream};


///////////////////////////////////////////////////////////////////////////////
//  Named Constants
///////////////////////////////////////////////////////////////////////////////

/// Format string for logfile names. Conforms to ISO 8601, except : has been replaced with _ to make Windows happy.
const FILE_TIMESTAMP_FORMAT: &str = "%Y-%m-%dT%H_%M_%S%.3f%z";

/// Format string for timestamps
#[cfg(not(test))]
const ENTRY_TIMESTAMP_FORMAT: &str = "%Y-%m-%dT%T%.9f";
#[cfg(test)]
pub const ENTRY_TIMESTAMP_FORMAT: &str = "%Y-%m-%dT%T%.9f";

/// Padding required to align text after Level label
const LEVEL_LABEL_WIDTH: usize = 9;

/// Padding to the left of the log message
const MESSAGE_LEFT_PADDING: usize = 3;

/// Logfile directory location
const LOGFILE_DIR: &str = "logs";

#[cfg(test)]
pub const STDOUT_FILENAME: &str = "logs/stdout_redirect.log";
#[cfg(test)]
pub const FILE_OUT_FILENAME: &str = "logs/file_out_redirect.log";


///////////////////////////////////////////////////////////////////////////////
//  Data Structures
///////////////////////////////////////////////////////////////////////////////

pub struct Receiver {
    logfile_prefix: &'static str,
    logger_rx: mpsc::Receiver<Command>,
    output_level: Level,
    output_stream: OutputStream,
    msg_count: Arc<AtomicU64>,
}


///////////////////////////////////////////////////////////////////////////////
//  Object Implementation
///////////////////////////////////////////////////////////////////////////////

impl Receiver {
    /// Fully-qualified constructor
    pub fn new(
        logfile_prefix: &'static str,
        logger_rx: mpsc::Receiver<Command>,
        output_level: Level,
        output_stream: OutputStream,
        msg_count: Arc<AtomicU64>,
    ) -> Self {
        Self {
            logfile_prefix,
            logger_rx,
            output_level,
            output_stream,
            msg_count,
        }
    }


    /*  *  *  *  *  *  *\
     * Utility Methods *
    \*  *  *  *  *  *  */

    /// Main loop for receiving logger commands
    pub fn main(&mut self) {
        let start_time = Local::now();
        println!(
            "{}: Entered LogReceiver thread.",
            start_time.format(ENTRY_TIMESTAMP_FORMAT)
        );

        // Open a logfile, creating logs directory if necessary
        let logfile_name = format!(
            "{}_{}.log",
            self.logfile_prefix,
            start_time.format(FILE_TIMESTAMP_FORMAT)
        );

        let mut path_buf = PathBuf::from(LOGFILE_DIR);
        if !path_buf.as_path().exists() {
            match fs::create_dir(path_buf.as_path()) {
                Ok(()) => (),
                Err(e) => panic!("Failed to create logs directory. Error: {}", e),
            }
        }

        path_buf.push(logfile_name);
        //OPT: *DESIGN* Could this be a member of Receiver?
        let mut logfile = match fs::File::create(path_buf.as_path()) {
            Ok(file) => file,
            Err(err) => panic!(
                "Failed to open logfile at {}. Error: {}",
                path_buf.as_path().display(),
                err
            ),
        };

        #[cfg(test)]
        {
            // Create verification files
            fs::File::create(STDOUT_FILENAME).unwrap_or_else(|err| {
                panic!(
                    "Encountered error '{}' while creating stdout verification file",
                    err
                )
            });
            fs::File::create(FILE_OUT_FILENAME).unwrap_or_else(|err| {
                panic!(
                    "Encountered error '{}' while creating file output verification file",
                    err
                )
            });
        }

        loop {
            // Check the channel for commands
            if let Ok(logger_cmd) = self.logger_rx.recv() {
                // Handle command based on type
                match logger_cmd {
                    /* Messages */
                    Command::LogMsg(log_tuple) => {
                        self.record_msg(&mut logfile, log_tuple)
                    }

                    /* Configuration Commands */
                    Command::SetOutputLevel(output_level) => {
                        self.output_level = output_level;
                    }
                    Command::SetOutputStream(output_stream) => {
                        self.output_stream = output_stream;
                    }

                    /* Flush */
                    Command::Flush(flush_ack_tx) => {
                        // If we're processing this command, all other previous commands have already
                        // been processed. Simple send the ACK back to the main thread.

                        // Only handle the failure case - nothing to do on success
                        if let Err(e) = flush_ack_tx.send(()) {
                            // Write an error into the log so we know something went wrong
                            let err_tuple = MsgTuple {
                                timestamp: Local::now(),
                                level: Level::Error,
                                fn_name: "LOG_RECEIVER_FLUSH_COMMAND".to_string(),
                                line: line!(),
                                msg: format!("Encountered SendError '{}' when sending flush ACK message.", e),
                            };

                            self.record_msg(&mut logfile, err_tuple);
                        }
                    }
                };
            }
        }
    }


    /*  *  *  *  *  *  *\
     * Helper Methods *
    \*  *  *  *  *  *  */

    fn record_msg(&mut self, logfile: &mut File, log_tuple: MsgTuple) {
        // Format the timestamp for recording
        let formatted_timestamp = log_tuple.timestamp.format(ENTRY_TIMESTAMP_FORMAT);

        if log_tuple.level >= self.output_level {
            // Console output
            if self.output_stream as u8 & OutputStream::StdOut as u8 != 0 {
                let log_color = match log_tuple.level {
                    Level::Trace => "\x1b[030;105m",
                    Level::Debug => "\x1b[030;106m",
                    Level::Info => "\x1b[030;107m",
                    Level::Warning => "\x1b[030;103m",
                    Level::Error => "\x1b[030;101m",
                    Level::Fatal => "\x1b[031;040m",
                };
                let msg_formatted = format!(
                    "{timestamp}: {color_set}[{level:^level_width$}]\x1b[0m {fn_name}() line {line}:\n{msg:>msg_leftpad$}",
                    timestamp   = formatted_timestamp,
                    color_set   = log_color,
                    level       = log_tuple.level.to_string(),
                    level_width = LEVEL_LABEL_WIDTH,
                    fn_name     = log_tuple.fn_name,
                    line        = log_tuple.line,
                    msg         = log_tuple.msg,
                    msg_leftpad = MESSAGE_LEFT_PADDING + log_tuple.msg.len(),
                );

                // Write to console
                println!("{}", msg_formatted);

                #[cfg(test)]
                {
                    // Add newline to formatted message for readability
                    let writeable_msg = format!("{}\n", msg_formatted);

                    // Write to stdout verification file
                    let mut stdout_redirect = fs::OpenOptions::new().append(true).open(STDOUT_FILENAME)
                        .unwrap_or_else(
                            |err| panic!("Encountered error '{}' while attempting to open stdout verification file.", err)
                        );
                    stdout_redirect.write_all(writeable_msg.as_bytes())
                        .unwrap_or_else(
                            |err| panic!("Encountered error '{}' while attempting to write to stdout verification file.", err)
                        );
                }
            }

            // File output
            if self.output_stream as u8 & OutputStream::File as u8 != 0 {
                let msg_formatted = format!(
                    "{timestamp}: [{level:^level_width$}] {fn_name}() line {line}:\n{msg:>msg_leftpad$}\n",
                    timestamp   = formatted_timestamp,
                    level       = log_tuple.level.to_string(),
                    level_width = LEVEL_LABEL_WIDTH,
                    fn_name     = log_tuple.fn_name,
                    line        = log_tuple.line,
                    msg         = log_tuple.msg,
                    msg_leftpad = MESSAGE_LEFT_PADDING + log_tuple.msg.len(),
                );

                //FEAT: Avoid spewing the same error if a file explodes or something
                logfile.write_all(msg_formatted.as_bytes())
                    .unwrap_or_else(
                        |err| eprintln!("{}: Encountered error '{}' while attempting to write to log file.", log_tuple.timestamp, err)
                    );

                #[cfg(test)]
                {
                    // Write to stdout verification file
                    let mut file_redirect = fs::OpenOptions::new().append(true).open(FILE_OUT_FILENAME)
                        .unwrap_or_else(
                            |err| panic!("Encountered error '{}' while attempting to open file output verification file.", err)
                        );
                    file_redirect.write_all(msg_formatted.as_bytes())
                        .unwrap_or_else(
                            |err| panic!("Encountered error '{}' while attempting to write to file output verification file.", err)
                        )
                }
            }
        }

        // Increment shared message count
        self.msg_count.fetch_add(1, Ordering::SeqCst);
    }
}
