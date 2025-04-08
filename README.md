# Py-avdu

An unofficial port of [Sammy-T](https://github.com/Sammy-T)'s [avdu](https://github.com/Sammy-T/avdu), re-written in Python by [Claude]() (and the hundreds of thousands of coders whose work it was trained on), main function added, and packaged for PyPI by [James Parrott](https://github.com/JamesParrott).  

I use this simply for peace of mind before factory resetting my phone, by exporting encrypted vault from [Aegis](https://getaegis.app/), simply as a check to make sure I can generate TOTP codes to access all my accounts in case of a problem reinstalling Aegis.  


## Overview

What's worse than rolling your own Crypto?  
Rolling your own Crypto with an LLM.

This is a little better than both of those for two reasons:
- Instead of rolling my crypto own completely from scratch, I gave Claude Sammy-T's avdu to start with and asked it to port it.
- This decrypts encrypted vaults only.  Encryption of the vaults in the
first place should be done by [Aegis](https://getaegis.app/).

Aegis is a fantastic app.  But its developers currently have [no intention](https://github.com/beemdevelopment/Aegis/issues/165#issuecomment-514096978) to support any other platform than Android.

I have no reason to be suspicious of Avdu in the slightest.
I've just done very little in Go, but am comfortable 
security-auditting Python code.  If you do discover a 
security concern or any other bug, please
raise an [issue](https://github.com/JamesParrott/py-avdu/issues),
and I'll do my best to fix it.  

If it can't be fixed, and it's an important bug, then ultimately
I'm willing to sunset the project.

## Alternatives

Avdu and Sammy-T's GUI Avda themselves, obviously
https://github.com/scollovati/Aegis-decrypt
https://github.com/Granddave/aegis-rs