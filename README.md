# UoGuelph CIS6510 Course Project

Research Project For The Detections Of Potential Email Spoofing Attacks Mentioned in [Composition Kills: A Case Study of Email Sender Authentication](https://www.usenix.org/conference/usenixsecurity20/presentation/chen-jianjun)

1. __Research Project Final Writeup__:   
https://github.com/AlanXu12/cis6510-email-spoofing-detector/blob/main/CIS6510_Project_Writeup_Pingfan_Xu_Yiwei_Guo.pdf

2. __Project Presentation Video__:  
https://youtu.be/Metf47dweEc

3. __Project Description__:  
Email is one of the most important and frequently used means of daily communication. With the convenience of email communication, email spoofing raises concerns for communication security when using email. The major email service vendors have already employed authentication checking mechanisms like DKIM, SPF, and DMARC to prevent email spoofing attacks. However, according to a recent publication at the 29th USENIX Security Symposium, the implement inconsistency among these three checking techniques would leave possibilities for email spoofing attacks. In this research project, we conduct studies on the issues mentioned in the publishing and give out our countermeasures toward them. We try all the mentioned attacks toward five major email service providers as an experiment. With the experimental result, we find some issues have already been fixed for particular vendors. As one of our experimental targets, Yahoo Mail has the worst prevention performance against the tested attacking cases among the five targets. Based on this finding, we implement a tool called Anti-Espoofer, which works as a complement of Yahoo Mail’s existing authentication checking mechanisms. We analyze the spoofing emails passed Yahoo’s checking and explain our countermeasures’ working principle in detail. Due to the time limitation, Anti-Espoofer is still on a primitive version. At the end of the project writeup, we also provide a possible direction to make Anti-Espoofer a mature product as a browser extension.

4. __Group Members__:
   * Pingfan Xu
   * Yiwei Guo
