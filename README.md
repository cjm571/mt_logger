# mt_logger

`mt_logger` is a multithreaded Rust logging library focused on traceability and ease-of-use via macros. Due to the nature of multithreading, it is best used in long-running programs with frequent or regular yields, such as web servers or game engines.

Logs are stored in a `logs` directory inside the current working directory when a program is launched. The directory will be created if it does not already exist. Log file names follow the format
`mt_log_YYYY-MM-DD_HH_MM_SS.ssss.log`

At initialization, a thread is created to receive log messages and commands from the main thread. Timestamps are set before sending in order to maintain complete traceability.

## Usage
The recommended method for using `mt_logger` is via macros. A global log sender is created by `mt_new!()`, so all further log messages and commands can be issues simply by calling the appropriate macro, such as `mt_log!()` to send a log message. No passing of references to a logger instance, or cloning of an `mpsc::Sender` required!

```rust
use mt_logger::*;

fn main() {
    // Initialize the mt_logger global instance
    mt_new!(Level::Info, OutputStream::Both);

    // Send a log message that WILL be output
    mt_log!(Level::Info, "Message {}: an INFO message", 1);
    // Send a log message that WILL NOT be output
    mt_log!(Level::Debug, "Message {}: a DEBUG message", 2);

    // Change the output stream to stdout only
    mt_stream!(OutputStream::StdOut);

    // Change the logging level
    mt_level!(Level::Trace);

    // Send a log message that WILL be output
    mt_log!(Level::Info, "Message {}: an INFO message", 3);
    // Send a log message that WILL be output
    mt_log!(Level::Trace, "Message {}: a TRACE message", 4);

    // Flush to ensure all messages reach the specified output
    mt_flush!().unwrap();

    // Get a count of the number of log messages
    let msg_count = mt_count!();
    println!("Messages logged: {}", msg_count);
}
```