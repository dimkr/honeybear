# honeybear

## Some History

Some time ago, I found a Chinese botnet that consists of SSH servers which run brute-force malware.

The operator's server connects to each node via SSH and uploads two files:
  * A list of IPv4 addresses to attack
  * A simple, script-kiddie grade brute-force tool compiled many years ago

Then, it starts the attack and [saves the results to a file](https://gist.github.com/dimkr/daa3f550b815c84b5804). The output is sent to the operator using a HTTP POST request. I was able to map the botnet and locate its operator.

## The Concept

I assume:
 * There's a large-scale botnet of SSH servers that expands using simple brute-force attacks.
 * I assume the malware that performs the brute-force attack spreads like a worm and runs on _all_ nodes, no just the first one.
 * The credentials used by the brute-force malware do not change over time.
 * My server is the next victim.

Theoretically, if I _mirror_ the attack, by using the same credentials used to attack my server to **attack the client**, one user/password combination _must_ work (because that's how the brute-force malware got there in first place). I tried this in small scale (with my own servers) and it worked perfectly.

## Implementation

This is _Dropbear 0.66_, hacked so:
 * Password authentication fails, always.
 * Plain-text credentials are written to the system log.
 * _dbclient_ is wrapped with _torify_ and executed after each authentication attempt, to try the same credentials against the client.

## Legal Information

The changes to _Dropbear_ are provided under the same license as the unmodified code.

Bear in mind that using **honeybear** is probably illegal in your country, just like plain SSH brute-force attacks. It is provided for the benefit of white hat hackers and system administrators.
