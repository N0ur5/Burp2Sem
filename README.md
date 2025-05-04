# Burp2Sem
My first attempt at a Burpsuite Extension. It is built to passively send temp copies of proxied HTML/JS to Semgrep. And yes, like most passive checks - it is full of -/+'s.... it's static analysis... 

Burp (as of `2025.2.4`) seems to do a great job batching these passive tasks up since they do take some time to complete and are resource intensive. There is likely enormous room for a performance boost but  ¯\\_(ツ)_/¯

## Prereq it
You need semgrep in your PATH. 

You will want to have a local copy of semgrep rules too. (`git clone https://github.com/returntocorp/semgrep-rules.git`)

## Git it
`git clone https://github.com/N0ur5/Burp2Sem.git`

## Mod it
Point this tool at a directory full of semgrep rules by modifying the `rulesDir` variable in `SemgrepScanCheck.java`

## Build it
`cd Burp2Sem`

`mvn clean package`

## Load it
`In BurpSuite -> Extensions -> Add -> Find SemgrepPassiveScanner-*.*.jar (in /target)`

## Use it
This is a passive check. Assuming you have semgrep installed locally... this thing should just cook "behind the scenes" and flag anything that semgrep would flag. You will need to take the finding and manually track down the actualy exploitability of any flagged Issues.

<img width="416" alt="image" src="https://github.com/user-attachments/assets/6b302ae7-834a-445f-856b-92047ce87326" />

There is also plenty to watch in the `Output` tab of `Extensions -> Installed -> Semgrep Passive Scanner` so that you can see what is going on.

<img width="613" alt="image" src="https://github.com/user-attachments/assets/772b0b36-bd17-4423-85ff-f912ffa92bb7" />



## TODO (Maybe... someday)
1. Fix highlighting syntax (Seems like maybe not possible with passive checks, might need to migrate to an active version too for this)
2. Fix severity/confidence
3. Move to a damon model for performance boost. Semgrep binary is launched for each js/html file that is analyzed currently. 
