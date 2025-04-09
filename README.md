# Py-avdu

An unofficial incomplete port of [Sammy-T](https://github.com/Sammy-T)'s [avdu](https://github.com/Sammy-T/avdu).  It was re-written in Python by [Claude](https://claude.ai/) (and the hundreds of thousands of coders whose work it was trained on), The main function was added and it was packaged for PyPI by [James Parrott](https://github.com/JamesParrott) (who should be held responsible).  

I use this myself, simply for peace of mind before factory resetting my phone, by exporting my encrypted vault from [Aegis](https://getaegis.app/), simply as a check to make sure I can generate TOTP codes without a phone, to access all my accounts in case of a problem reinstalling Aegis.  

Before deleting any credentials or factory resetting any devices, please verify that you really 
can generate the same correct codes from your own backup vault, as from the original authenticator app
the backup was taken from.


## Overview

What's worse than rolling your own Crypto?  
Rolling your own Crypto with an LLM.

Py-Avdu is a little bit better than both of those cases for two reasons:
- Instead of rolling my own crypto completely from scratch I gave Claude, Sammy-T's avdu, and asked it to port it.
- This decrypts encrypted vaults only.  Encryption of the vaults in the first place should be done by [Aegis](https://getaegis.app/).  Py-avdu should only be used locally.

Aegis is a fantastic app.  But its developers currently have [no intention](https://github.com/beemdevelopment/Aegis/issues/165#issuecomment-514096978) to support any other platform than Android.

I have no reason to be suspicious of Avdu in the slightest - I'm personally just far more comfortable security-auditting Python code than Go code.  

If you do discover a bug, please raise an [issue](https://github.com/JamesParrott/py-avdu/issues),
and I'll do my best to fix it.  If a bug that's a major security 
concern can't be fixed or worked around, then ultimately I will sunset 
this project.

Py-Avdu does generate TOTP codes correctly from a password-encrypted Aegis backup vault (from my own one at least).  
However at the time of writing, no further functionality is implemented - Py-Avdu is definitely an incomplete port of Avdu.  


## Beware ye, would be Vibe Coders.
Claude's code to decrypt my vault worked great.  Unfortunately
 ChatGPT's port of Avdu's TOTP generator produced incorrect TOTP codes.  Luckily
there is a trustworthy library from [PyAuth](https://github.com/pyauth) (PyOTP) to use 
instead which fits the bill precisely.  


## Alternatives
 - Obviously the original [Avdu](https://github.com/Sammy-T/avdu) and Sammy-T's more user 
friendly [Avda](https://github.com/Sammy-T/avdu) based on it.
 - https://github.com/Granddave/aegis-rs
 - https://github.com/scollovati/Aegis-decrypt