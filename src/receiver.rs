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

use std::sync::mpsc;

use std::fs;
use std::io::prelude::*;
use std::path::PathBuf;

use chrono::Local;

use crate::{Command, FilterLevel, OutputType};


///////////////////////////////////////////////////////////////////////////////
//  Named Constants
///////////////////////////////////////////////////////////////////////////////

/// Padding required to align text after FilterLevel label
const LEVEL_LABEL_WIDTH: usize = 9;

/// Padding to the left of the log message
const MESSAGE_LEFT_PADDING: usize = 3;

#[cfg(test)]
pub const STDOUT_FILENAME: &str = "logs/stdout_redirect.log";
#[cfg(test)]
pub const FILE_OUT_FILENAME: &str = "logs/file_out_redirect.log";


///////////////////////////////////////////////////////////////////////////////
//  Data Structures
///////////////////////////////////////////////////////////////////////////////

pub struct Receiver {
    logger_rx: mpsc::Receiver<Command>,
    filter_level: FilterLevel,
    output_type: OutputType,
}


///////////////////////////////////////////////////////////////////////////////
//  Object Implementation
///////////////////////////////////////////////////////////////////////////////

impl Receiver {
    /// Fully-qualified constructor
    pub fn new(
        logger_rx: mpsc::Receiver<Command>,
        filter_level: FilterLevel,
        output_type: OutputType,
    ) -> Self {
        Self {
            logger_rx,
            filter_level,
            output_type,
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
            start_time.format("%Y-%m-%d %T%.3f")
        );

        // Open a logfile, creating logs directory if necessary
        let logfile_dir = "logs";
        let logfile_name = format!(
            "sandcasting_log_{}.log",
            start_time.format("%F_%H_%M_%S%.3f")
        );

        let mut path_buf = PathBuf::from(logfile_dir);
        if !path_buf.as_path().exists() {
            match fs::create_dir(path_buf.as_path()) {
                Ok(()) => (),
                Err(e) => panic!("Failed to create logs directory. Error: {}", e),
            }
        }

        path_buf.push(logfile_name);
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
            fs::File::create(STDOUT_FILENAME)
                .unwrap_or_else(
                    |err| panic!("Encountered error '{}' while creating stdout verification file", err)
                );
            fs::File::create(FILE_OUT_FILENAME)
                .unwrap_or_else(
                    |err| panic!("Encountered error '{}' while creating file output verification file", err)
                );
        }

        loop {
            // Check the channel for commands
            if let Ok(logger_cmd) = self.logger_rx.recv() {
                let timestamp = Local::now().format("%Y-%m-%d %T%.3f");

                // Handle command based on type
                match logger_cmd {
                    /* Messages */
                    Command::LogMsg(log_tuple) => {
                        if log_tuple.level >= self.filter_level {
                            // Console output
                            if self.output_type as u8 & OutputType::Console as u8 != 0 {
                                let log_color = match log_tuple.level {
                                    FilterLevel::Trace => "\x1b[030;105m",
                                    FilterLevel::Debug => "\x1b[030;106m",
                                    FilterLevel::Info => "\x1b[030;107m",
                                    FilterLevel::Warning => "\x1b[030;103m",
                                    FilterLevel::Error => "\x1b[030;101m",
                                    FilterLevel::Fatal => "\x1b[031;040m",
                                };
                                let msg_formatted = format!(
                                    "{timestamp}: {color_set}[{level:^level_width$}]\x1b[0m {fn_name}() line {line}:\n{msg:>msg_leftpad$}",
                                    timestamp   = timestamp,
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
                            if self.output_type as u8 & OutputType::File as u8 != 0 {
                                let msg_formatted = format!(
                                    "{timestamp}: [{level:^level_width$}] {fn_name}() line {line}:\n{msg:>msg_leftpad$}\n",
                                    timestamp   = timestamp,
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
                                        |err| eprintln!("{}: Encountered error '{}' while attempting to write to log file.", timestamp, err)
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
                    }

                    /* Configuration Commands */
                    Command::SetFilterLevel(filter_level) => {
                        self.filter_level = filter_level;
                    }
                    Command::SetOutput(output_type) => {
                        self.output_type = output_type;
                    }
                };
            }
        }
    }
}
