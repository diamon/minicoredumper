minicoredumper
==============

This project is maintained by:

[![Linutronix](https://raw.githubusercontent.com/Linutronix/.github/master/images/lx_logo_padded.png)](https://www.linutronix.de)


Overview
--------

minicoredumper provides an alternate core dump facility for Linux
to allow minimal and customized crash dumps. It is composed
primarily of 3 parts:

1. minicoredumper - a customizable core dump application to replace
                    the default Linux core dump facility

2. libminicoredumper - a library allowing applications to register
                       data for dumping

3. minicoredumper_regd - a service to allow multiple applications
                         to dump their data on demand or if any of
                         the applications crash

License
-------

Please view the file `COPYING` for copyright and license information.

Installation
------------

The minicoredumper package uses autotools:

```
$ ./configure
$ make
$ sudo make install
```

In the `etc` directory there are sample configuration files.

To inform Linux to use the minicoredumper for the core dump facility:

```
$ echo '|/usr/sbin/minicoredumper %P %u %g %s %t %h %e' | \
       sudo tee /proc/sys/kernel/core_pattern
$ echo 0x7fffffff | sudo tee /proc/sys/kernel/core_pipe_limit
```

Documentation
-------------

The following man pages are provided with this package:

- [libminicoredumper (7)](https://www.linutronix.de/minicoredumper/man/man7/libminicoredumper.7.html)
- [minicoredumper (1)](https://www.linutronix.de/minicoredumper/man/man1/minicoredumper.1.html)
- [minicoredumper.cfg.json (5)](https://www.linutronix.de/minicoredumper/man/man5/minicoredumper.cfg.json.5.html)
- [minicoredumper.recept.json (5)](https://www.linutronix.de/minicoredumper/man/man5/minicoredumper.recept.json.5.html)
- [minicoredumper_regd (1)](https://www.linutronix.de/minicoredumper/man/man1/minicoredumper_regd.1.html)
- [minicoredumper_trigger (1)](https://www.linutronix.de/minicoredumper/man/man1/minicoredumper_trigger.1.html)
- [coreinject (1)](https://www.linutronix.de/minicoredumper/man/man1/coreinject.1.html)
- [mcd_dump_data_register_bin (3)](https://www.linutronix.de/minicoredumper/man/man3/mcd_dump_data_register_bin.3.html)
- [mcd_dump_data_register_text (3)](https://www.linutronix.de/minicoredumper/man/man3/mcd_dump_data_register_text.3.html)
- [mcd_dump_data_unregister (3)](https://www.linutronix.de/minicoredumper/man/man3/mcd_dump_data_unregister.3.html)

Support
-------

Website: https://linutronix.de/minicoredumper

Mailing List: https://lists.linutronix.de/mailman/listinfo/minicoredumper

Issue Tracker: https://github.com/diamon/minicoredumper/issues

Git Repository: https://github.com/diamon/minicoredumper

Demo
----

This packages provides an example application to test the
minicoredumper. The example application is not built by default.
This must be activated with the `--with-minicoredumper_demo`
argument for configure.

The example application `minicoredumper_demo` uses libminicoredumper
to register variables. If it is run with no command line arguments,
it crashes deliberately, which should trigger the minicoredumper.
The example also registers with minicoredumper_regd. When an
application crashes, the registered data of the example application
can be dumped as well (depending on the recept file).

The demo can be performed by running the example program twice. One
instance that registers itself, waits, and exits gracefully, and
another instance that crashes. Assuming minicoredumper is installed
and activated, minicoredumper_regd is running and `live_dumper` is
enabled in the recept file, the demo can be executed with the
following commands:

```
$ minicoredumper_demo 6 & sleep 3 && minicoredumper_demo
```

This will start one instance of minicoredumper_demo in the background
that will gracefully exit after 6 seconds. 3 seconds after starting
the first instance, a second instance of minicoredumper_demo is
started in the foreground that will crash immediately.

In the minicoredumper `base_dir` there should now be a directory
containing a core file and the dump data from the second (crashed)
instance of minicoredumper_demo. In that directory there should also
be the dump data from the first instance of minicoredumper_demo
(that had a graceful exit).
