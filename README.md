# Burp2Sem
Burpsuite Extension built to passively send copies of proxied HTML/JS to Semgrep. And yes, like most passive checks - it is full of -/+'s.... it's Semgrep static analysis. Burp (as of 2025.2.4) seems to do a great job batching these passive tasks up since they do take some time to complete. There is likely enormous room for a performance boost but  ¯\_(ツ)_/¯

## Git it
`git clone https://github.com/N0ur5/Burp2Sem.git`

## Mod it
Point this tool at a directory full of semgrep rules by modifying the "rulesDir" variable in `SemgrepScanCheck.java`

## Build it
`cd Burp2Sem`

`mvn clean package`

## Load it
`In BurpSuite -> Extensions -> Add -> Find SemgrepPassiveScanner-*.*.jar (in /target)`

## Use it
This is a passive check. Assuming you have semgrep installed locally... this thing should just cook "behind the scenes" and flag anything that semgrep would flag. You will need to take the finding and manually track down the actualy exploitability of any flagged Issues.

<img width="416" alt="image" src="https://github.com/user-attachments/assets/6b302ae7-834a-445f-856b-92047ce87326" />

## TODO (Maybe... someday)
1. Fix highlighting syntax (Seems like maybe not possible with passive checks, might need ot migrate to an active version too for this)
2. Fix severity/confidence
3. Move to a damon model for performance boost. Semgrep binary is launched for each js/html file that is analyzed. 
