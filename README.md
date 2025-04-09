# Py-avdu

An unofficial port of [Sammy-T](https://github.com/Sammy-T)'s [avdu](https://github.com/Sammy-T/avdu), re-written in Python by [Claude]() (and the hundreds of thousands of coders whose work it was trained on), main function added, and packaged for PyPI by [James Parrott](https://github.com/JamesParrott).  

I use this myself, simply for peace of mind before factory resetting my phone, by exporting my encrypted vault from [Aegis](https://getaegis.app/), simply as a check to make sure I can generate TOTP codes without a phone, to access all my accounts in case of a problem reinstalling Aegis.  


## Overview

What's worse than rolling your own Crypto?  
Rolling your own Crypto with an LLM.

This is a little better than both of those for two reasons:
- Instead of rolling my crypto own completely from scratch I gave Claude, Sammy-T's avdu, and asked it to port it.
- This decrypts encrypted vaults only.  Encryption of the vaults in the first place should be done by [Aegis](https://getaegis.app/).

Aegis is a fantastic app.  But its developers currently have [no intention](https://github.com/beemdevelopment/Aegis/issues/165#issuecomment-514096978) to support any other platform than Android.

I have no reason to be suspicious of Avdu in the slightest - I'm personally just far more comfortable security-auditting Python code than Go code.  

If you do discover a bug, please raise an [issue](https://github.com/JamesParrott/py-avdu/issues),
and I'll do my best to fix it.  If a bug that's a major security 
concern can't be fixed or worked around, then ultimately I will sunset 
this project.

## Alternatives

 - Obviously the original [Avdu](https://github.com/Sammy-T/avdu) and Sammy-T's more user 
friendly [Avda](https://github.com/Sammy-T/avdu) based on it.
 - https://github.com/Granddave/aegis-rs
 - https://github.com/scollovati/Aegis-decrypt