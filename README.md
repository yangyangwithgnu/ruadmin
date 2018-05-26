**捐赠**：支付宝 yangyangwithgnu@yeah.net ，支付宝二维码（左），微信二维码（右）
<div align="center">
<img src="https://raw.githubusercontent.com/yangyangwithgnu/yangyangwithgnu.github.io/master/pics/alipay_donate_qr.png" alt=""/>
<img src="https://raw.githubusercontent.com/yangyangwithgnu/yangyangwithgnu.github.io/master/pics/wechat_donate_qr.png" alt=""/><br>
</div>

**二手书**：书，我提高开发技能的重要手段之一，随着职业生涯的发展，书籍也在不断增多，对我而言，一本书最多读三遍，再往后，几乎没有什么营养吸收，这部分书对我已基本无用，但对其他人可能仍有价值，所以，为合理利用资源，我决定低价出售这些书，希望达到两个目的：0）用售出的钱购买更多新书（没当过雷锋的朋友 (๑´ڡ`๑)）；1）你低价购得需要的书（虽然二手）。到 https://github.com/yangyangwithgnu/used_books 看看有无你钟意的。

<hr />

<h1 align="center">are you admin?：ruadmin 给你答案</h1>
<div align="center">
<img src="https://github.com/yangyangwithgnu/ruadmin/blob/master/pic/ascii-art%20logo.png" alt=""/><br>
</div>

ruadmin is a logon **Brute Force** tool, for windows privilege escalation, but also system management. ruadmin has been developed in the hope that it will be useful for penetration tester and everyone else that plans to use it for ethical reasons. plz do not use in any illegal purposes. 

there are some command line options: 
  * --help: show this summary info of all options. 
  * --user: by default ruadmin checks all windows OS users (inclue hidden user like yangyangwithgnu$). this option checks only one user. 
  * --base-passwds-file: by default ruadmin load built-in base passwds list (about 40,000 chinese and europe-america and hackers weakness passwds). this option load base passwords from file. 
  * --se-keywords-file: ruadmin handle base passwds and social engineering keywords, to generate new passwds dict. this option load social engineering keywords from file. **attention**, keywords will make passwds dict become verrrrrrry huge, so, you'd better set one or two keywords. 
  * --one-quit: by default ruadmin checks all passwords for all users. this option quit after the first passwd found for any user. 

happy hacking! 

(BTW, u can get the exe in Release/ https://github.com/yangyangwithgnu/ruadmin/tree/master/Release/)

papers: 
《高收益的笨办法：暴破在Windows提权中的应用》 http://www.freebuf.com/articles/system/170709.html 
《暴破助功提权：ruadmin》 https://bbs.ichunqiu.com/thread-40877-1-1.html
