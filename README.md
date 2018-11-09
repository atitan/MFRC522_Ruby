# MFRC522_Ruby

[![Gem Version](https://badge.fury.io/rb/mfrc522.svg)](https://badge.fury.io/rb/mfrc522)

This project is aiming to provide easy access to MIFARE RFID tags using MFRC522 and Raspberry Pi.

The code itself can be ported to other platform with little effort since it's purely written in Ruby.

Inspired by [miguelbalboa/rfid](https://github.com/miguelbalboa/rfid) and [Elmue/electronic RFID Door Lock](http://www.codeproject.com/Articles/1096861/DIY-electronic-RFID-Door-Lock-with-Battery-Backup).

## Installation

Ruby version 2.3+ is required.

You can install it by doing `gem install mfrc522` or using bundler.

## Documentation

RDoc is available at [RubyDoc](http://www.rubydoc.info/github/atitan/MFRC522_Ruby/master).

## Hardware

This library assumes you have the reader connected to SPI0 CE0 on Raspberry Pi, and the NRSTPD(RST) pin is connected to BCM24.

If not, adjust the parameters when calling MFRC522 initialize method.

## Supported RFID tags

Models supported and have been tested by the author:

*   MIFARE Classic
*   MIFARE Ultralight
*   MIFARE Ultralight C
*   MIFARE DESFire EV1, without ISO-7816 APDU
*   MIFARE DESFire EV2, without ISO-7816 APDU and new features since EV1

Models implemented but not tested:

*   MIFARE Ultralight EV1

Models under development:

*   MIFARE Plus

If the card model you want to use is not on the list, you can implement it on top of the `PICC` class.

The library provide basic access to ISO 14443-3 and ISO 14443-4 protocol.

## Get started

Check out files in folder `test` for example usage.

You have to rescue exceptions yourself.

## Known Issue

The underlying library `pi_piper` we used is known to cause SegFault if you use it along with Gtk3 on Respbian Stretch, which comes with Ruby 2.3.3 by default. Upgrading Ruby to newer version is likely to solve the issue. Ref: https://github.com/atitan/MFRC522_Ruby/issues/4
