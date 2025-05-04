# Burp2Sem
Burpsuite Extension built to passively send copies of proxied HTML/JS to Semgrep. And yes, like most passive checks - it is full of -/+'s.... it's Semgrep static analysis. Burp (as of 2025.2.4) seems to do a great job batching these passive tasks up since they do take some time to complete. There is likely enormous room for a performance boost but  ¯\_(ツ)_/¯

## Git it
`git clone https://github.com/N0ur5/Burp2Sem.git`

## Build it



## TODO (Maybe... someday)
1. Fix highlighting syntax (Seems like maybe not possible with passive checks, might need ot migrate to an active version too for this)
2. Fix severity/confidence
3. Move to a damon model for performance boost. Semgrep binary is launched for each js/html file that is analyzed. 
