# rootme
 post exploitation tool for suggesting local kernel exploits

## What is rootme?

rootme is a post exploitation tool which suggests local kernel exploits based on the installed kernel version.

## Usage

At this point, rootme supports two ways:

Detect kernel and suggest exploit:

> python rootme.py -d

Manually name the version of the kernel:

> python rootme.py -m 4.4.2

## Exploit database

the exploit database is currently quite limited and only contains 5 entries. In the next versions, the database will be extended.

## Screenshot

![Screenshot](https://github.com/pbkangafoo/rootme/blob/main/rootme_screenshot.jpg "rootme screenshot")
