# Contributing

Bug reports, test results and patches are welcome.

## Reports

The most useful report right now is "I ran it against a real IPX network".
Say what the client was (the operating system, its IPX stack and version,
the network card and its frame type), how the relay was started, and what
`gork-relay -v` printed. A packet capture of the exchange is worth more
than any description.

For a bug, give the command line, what you expected and what happened.
Leave your API key out of anything you post: the relay carries it in the
clear, and so does a capture.

## Patches

- Run `make check` before sending; it must pass. A change to the SPX or
  framing code should come with a check in `test/relaytest.py`.
- Keep to the style of the code around the change: four spaces, C99,
  comments that say why. No new dependencies beyond libc and OpenSSL
  without discussing it first.
- One change per commit, with a message that says what it does and why.
- State how the change was tested, and on what. "Not tested on a real
  ring" is a fine thing to say; an untested claim that something works is
  not.

## Licence

gork-relay is under the GNU General Public License, version 3 or later
(see [LICENSE](LICENSE)). By sending a change you agree that it is
published under the same licence, and state that you have the right to
submit it.
