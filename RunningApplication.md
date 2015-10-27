# Introduction #

This page describes how to run the blkmon application.

# Starting the application #

## First-time startup ##

To start the application for the first time, it is best to use a semi-development mode of operation.

The following cmds will start the application in the foreground. The application logs will be created in /tmp with the common prefix "blk.log":

```
cd my-blkmon-dir
twistd -noy blk.tac -l /tmp/blk.log
```

If there are syntax errors, the cmd will stop immediately with an error message.

To see other errors, look at the log files.

## Running as a daemon ##

In production, the following cmd will run the application as a daemon in the background. Log data will be sent to OS syslog:

`twistd -y blk.tac --syslog`

# Logging #

The application will log error messages and other status to the log files.

Each log file will be 1 MB in size.

Log files are numbered in reverse order. So the files from most recent to oldest would be for example:

  * blk.log (most recent log)
  * blk.log.1
  * blk.log.2
  * blk.log.3
  * . . .
  * blk.log.34 (oldest log)

You can watch the server activity with the usual:

` tail -f /tmp/blk.log`

but be aware that a new log file will start after 1 MB of data has been logged.

To see the consolidated log data in chronological order, you could use the following cmds:

```
cd \tmp
cat `ls -Ftr blk.log*` > myblk.log
rm \tmp\blk.log*
less myblk.log
```

# Web GUI interface #

A simple Web GUI interface is provided for use.

For more information, see [WebGUI](WebGUI.md)


# Stopping the application #

To stop the app:

`pkill twistd`