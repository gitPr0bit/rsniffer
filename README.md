# snifferlib
**snifferlib** is a library that lets you capture TCP/UDP traffic in promiscuous mode and produce a textual report.<br>
## Features
 - [x] choose capture device
 - [x] choose the output file
 - [x] set a filter using [BPF](https://biot.com/capstats/bpf.html) syntax
 - [x] choose how to sort the traffic
 - [x] select a time interval after which an updated version of the report is generated
 - [x] pause, resume and stop the sniffing process at any time

## Report
The report lists, for each of the observed network address/port pairs, the transported protocols, the cumulated number of bytes and packets transmitted, and the timestamp of the first and last occurrence of information exchange.<br>
A table like this one is printed in the output file:
| SRC_IP        | DST_IP       | SRC_PORT | DST_PORT | PROTOCOLS | BYTES | PACKETS # | FIRST TIMESTAMP     | LAST TIMESTAMP      |
|---------------|--------------|----------|----------|-----------|-------|-----------|---------------------|---------------------|
| 52.97.186.114 | 192.168.1.49 | 443      | 52583    | TCP       | 26 KB | 21        | 2022-11-07 22:31:01 | 2022-11-07 22:31:01 |
| 52.98.159.2   | 192.168.1.49 | 443      | 52584    | TCP       | 13 KB | 38        | 2022-11-07 22:31:01 | 2022-11-07 22:31:02 |
|               |              |          |          |           |       |           |                     |                     |

## Documentation
To get a better understanding of how to use this library, have a look at the documentation.<br>
You can generate it from the source code by launching `cargo doc --lib --no-deps`.<br>
This will generate the documentation in `target/doc/snifferlib`.<br><br>


# rsniffer
**rsniffer** is an application that takes full advantage of snifferlib.
The application captures TCP/UDP traffic in promiscuous mode and generates a report to a file of choice.

## Features
 - [x] choose capture device
 - [x] choose the output file
 - [x] set a filter using [BPF](https://biot.com/capstats/bpf.html) syntax
 - [x] choose how to sort the traffic
 - [x] select a time interval after which an updated version of the report is generated
 - [x] pause, resume and stop the sniffing process at any time

The application also takes care of properly indicating any failure of the sniffing process, providing meaningful and actionable feedback.
When the sniffing process is active, a suitable indication is provided to the user.

## Visuals
![rsniffer running](screenshots/rsniffer_running?raw=true)

    rsniffer paused        |    rsniffer stopped
:-------------------------:|:-------------------------:
![](screenshots/rsniffer_paused?raw=true)  |  ![](screenshots/rsniffer_stopped?raw=true)

## Installation
Within a particular ecosystem, there may be a common way of installing things, such as using Yarn, NuGet, or Homebrew. However, consider the possibility that whoever is reading your README is a novice and would like more guidance. Listing specific steps helps remove ambiguity and gets people to using your project as quickly as possible. If it only runs in a specific context like a particular programming language version or operating system or has dependencies that have to be installed manually, also add a Requirements subsection.
