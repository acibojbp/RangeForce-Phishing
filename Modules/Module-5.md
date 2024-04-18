# Understanding RTLO Spoofing

In this module, you will learn how the right-to-left override character can be used to spoof suspicious filenames, how to identify files using this spoofing technique via multiple methods, and how it can be detected.

Learning outcomes

Upon completion of this module, learners will be able to

- Understand how RTLO can be used to spoof file names.
- Identify RTLO spoofing using static and dynamic analysis.
- Know how RTLO spoofing can be detected.

## Contents
- [RTLO Character](#rtlo-character)
- [Other Unicode Spoofing Methods](#other-unicode-spoofing-methods)
- [Analyze the Suspicious Attachment](#analyze-the-suspicious-attachment)
- [Static Analysis](#static-analysis)
   - [Rename the File in Explorer](#rename-the-file-in-explorer)
   - [View the File in the Terminal](#view-the-file-in-the-terminal)
- [Dynamic Analysis](#dynamic-analysis)

## RTLO Character

The **Right-to-Left Override (RTLO)** character is a **Unicode** character that can be used to modify the direction of text within a string, especially when mixing left-to-right and right-to-left scripts. The character's Unicode number is **U+202E**. The legitimate purpose of the RTLO character is to **manage text direction and formatting when embedding right-to-left text within a primarily left-to-right text string or vice versa**, such as including an Arabic or Hebrew word in an English sentence. It is part of the Unicode character set and is used to override the default text direction, ensuring appropriate rendering for mixed-language text.

When used maliciously in a filename, the RTLO character can make the name appear less suspicious to users as it may appear to be different than it actually is. It's important to note that the operating system interprets the filename without the RTLO character, which is how it can be used to spoof a filename.

Here's an example of an executable file with an RTLO character concealing the actual file extension:

`image‮gpj.exe`

In this example, the RTLO character is placed after the word **image**. Consequently, the remaining part of the filename, **exe.jpg**, is displayed to the user in reverse, however, the operating system still reads the filename without the RTLO character, revealing the true filename as `imagegpj.exe` , which is an executable file. When a user attempts to open this "image", an executable file will run instead, which could potentially contain malicious code. To further lower suspicion, the executable file could be designed to open an image file as well as run malicious code in the background.

The RTLO character can be found using the **Character Map** application in Windows:

![Screenshot 2024-04-17 181258](https://github.com/acibojbp/RangeForce-Phishing/assets/164168280/594bc580-a590-485a-a332-a1b6eb9eeb2d)

- Answer the questions.

What is the Unicode number of the RTLO character?  
Ans: `U+202E`  

What is the primary legitimate purpose of the RTLO character?  
To spoof file extensions in order to deceive users.  
**To manage text direction and formatting in right-to-left languages.**  
To reverse the order of characters in a filename for aesthetic purposes.  
To prevent the operating system from interpreting a file correctly.  

How can the RTLO character potentially be used maliciously in a filename?  
By changing the encoding of the filename.  
**By concealing the actual file extension.**  
By making the file invisible in the file explorer.  
By deleting parts of the filename.  

Take a look at the following filename, where `?` represents the RTLO character: `document?fdp.exe`  
How would this filename be displayed to a user in a Windows OS? (with file extensions visible)  
Ans: `documentexe.pdf`  


## Other Unicode Spoofing Methods

Unicode is often leveraged to spoof URLs in phishing emails to make hyperlinks appear legitimate. You are likely aware that attackers use URLs similar to legitimate URLs to trick recipients into clicking them. At a glance, these URLs appear genuine, but after a closer look, you may notice a small difference.

For example, a `1` can look like a lowercase **L** ( `l`), as demonstrated below:

Original website: `paypal.com`
Misleading hyperlink: `paypa1.com`
Unicode provides a few more possibilities for attackers, which are almost impossible to detect by the human eye.

Here are two examples:

1. **Homoglyphs**

Homoglyphs are characters that visually resemble other characters, which can be used to deceive users. For instance, using the Cyrillic letter "а" (U+0430) instead of the Latin letter "a" (U+0061) in a filename or URL.

Can you spot the difference between the following URLs?

`facebook.com`  
`facebооk.com`  
`fɑcebook.com`  
`fасеbооk.соm`  

> Note: Due to the font used above, the difference is quite obvious, however, many standard fonts make the difference virtually impossible to spot. Here are the same links shown in Notepad:

![Screenshot 2024-04-17 181730](https://github.com/acibojbp/RangeForce-Phishing/assets/164168280/d059dab5-336f-4072-961d-684d4e3aa2da)

Most letters in the alphabet have a convincing alternative in Unicode, which can be very deceptive when used to create malicious URLs or filenames.

![Screenshot 2024-04-17 181829](https://github.com/acibojbp/RangeForce-Phishing/assets/164168280/8d88dbcd-107c-4654-b70a-c9c53cd1fa30)

2. **Zero-Width Characters**

Zero-width characters, such as zero-width space (U+200B) and zero-width non-joiner (U+200C), can be used to hide or obfuscate information within URLs or filenames. Attackers may use these characters to bypass detection or create misleading links or filenames.

Can you spot the difference between the following filenames?

`notmalware.exe`  
`not​malware​.exe`  

Try converting the second filename to Unicode [here](https://www.branah.com/unicode-converter).

![Screenshot 2024-04-17 181912](https://github.com/acibojbp/RangeForce-Phishing/assets/164168280/18f53e66-cf1a-487b-947d-e5115234fc09)

- Answer the questions.

Which Unicode character can be used to replace the Latin letter "a" in a URL to deceive recipients?  
U+0130  
U+0230  
U+0330  
**U+0430**  
U+0530  

Which of the following are examples of zero-width characters used to obfuscate information in filenames? (Select 3 answers)  
**Zero-width space (U+200B)**  
Zero-width hyphen (U+2010)  
**Zero-width non-breaking space (U+FEFF)**  
**Zero-width non-joiner (U+200C)**  
Zero-width linker (U+200F)  


## Analyze the Suspicious Attachment

Glenda Backus, an HR Specialist at Commensurate Technology (ComTech), received an email from what appears to be an IT contractor requiring the review and approval of an infrastructure upgrade plan document. The email implies some urgency around reviewing the document as soon as possible. Glenda attempted to open the document and then reported the email to the SOC for investigation as the document did not open and now the files on her laptop are encrypted.

Go to Outlook Web Access and open the email from Glenda with the subject '**This looks weird**'. Download the attachment to the desktop to analyze the file and its contents. You will notice that the file has been compressed. This is a common technique used by attackers to [obfuscate files](https://attack.mitre.org/techniques/T1027/). You should extract the contents of the **.7z** file and find out what it really is.

> Note: 7zip is used to compress this file because the built-in Windows Archiving Utility does not allow archiving of files with RTLO characters in the name.

> Note: Before you extract the file from the email, remember that you should never open or analyze a file on a machine that is connected to the network. You should only analyze and run files in a sandbox environment on a host computer that you are willing to reset/wipe completely, as you could lose all content and functionality. Be careful not to accidentally open the file in your live environment. Some malware can break out of the sandbox and infect the host machine. In this instance, you may use the environment provided in this lab as your sandbox.


- Log in to Outlook Web Access.
	- Username: emmanuel.toller@commensuratetechnology.com
	- Password: t0tallySecre7?
	- Set a time zone for Outlook.
- Download the attached .7z file.
- Open the folder where the file is located and extract it by right-clicking the file and selecting Extract Here.
- Answer the question.

![Screenshot 2024-04-17 182321](https://github.com/acibojbp/RangeForce-Phishing/assets/164168280/13ea927e-d6b7-4ed4-b431-235cab872fde)

![Screenshot 2024-04-17 182336](https://github.com/acibojbp/RangeForce-Phishing/assets/164168280/43f3e185-859b-4517-b436-18e35477c63a)

After extracting the contents of the zipped folder, what does the file extension initially appear to be?
Ans: `.pdf`

## Static Analysis
As you can see, the file appears to be a PDF document, however, this is not the case. The attacker has used the RTLO character to masquerade the filename to make it appear benign. The icon has also been changed to further disguise the file as a PDF file.

Fortunately, there are several ways to identify suspicious anomalies in the attachment's filename...

### Rename the File in Explorer

One approach to detecting a suspicious filename is by attempting to rename the file. Before you try to rename the file, you should enable file extensions.

![Screenshot 2024-04-17 182539](https://github.com/acibojbp/RangeForce-Phishing/assets/164168280/4878d26b-ad25-475e-b870-0d0deb6f1e3a)

Next, right-click the file and choose Rename.

When you rename a regular file, the filename will be highlighted and the file extension will not. Look at what is highlighted in this filename.

- Enable file extensions in File Explorer.
- Try to rename the file and observe what part of the filename is highlighted.
- Answer the question.

What is the actual file extension?
Ans: `.exe`

### View the File in the Terminal

Another way to identify a suspicious filename is to view the filename in the terminal (or command prompt).

Open the command prompt and run the following commands to see the filename in the terminal window:

1. Use `cd` to navigate to the folder where the file is located.
2. Use `dir` to list files in the directory.

As you can see, the RTLO character does not take effect in the terminal. Instead, it appears as another symbol, and the text is not reversed.

![Screenshot 2024-04-17 182746](https://github.com/acibojbp/RangeForce-Phishing/assets/164168280/ba329dd3-f968-4908-8c61-4aea8c2dd382)

Depending on the version of the OS, the RTLO character may appear as some unknown symbols, a replacement character � , or a long space.

> Note: The malicious attachment is an executable (.exe) file. Exe is the same in reverse and is therefore difficult to obfuscate using the RTLO character. Other executable types such as .msi, .bat, .cmd, .vbs, and .ps1 are harder to spot when displayed in reverse.

## Dynamic Analysis

The file has previously been uploaded to and scanned by [Hybrid Analysis](https://www.hybrid-analysis.com/) to assess its reputation and behavior. You can access the scan results [here](https://www.hybrid-analysis.com/sample/86cc510835831f1fb61d3cfbcb24f301f36d8a182bfe48a0b50640e21ffce93b/6469fa8efd2d19f45200f951).

As you will see, the application has a lot of nefarious functionalities, such as keylogging and suspicious API calls. The file has been identified as **Hades ransomware**, which is extremely dangerous. This ransomware has the potential to quickly propagate within an organization, encrypting files and demanding payment for their release.

Considering the example provided here, do you think you would have been tricked into attempting to open the "document" that was attached to the email?

![Screenshot 2024-04-17 183131](https://github.com/acibojbp/RangeForce-Phishing/assets/164168280/b49f30a0-859d-4a1b-a61f-a65434079a4a)

> Note: You might have noticed that Hybrid Analysis, in this case, didn't detect the Right-to-Left Override masquerading technique . This serves as an important reminder that even advanced automated analysis tools may not always recognize every tactic employed by threat actors to disguise their payloads. It emphasizes the importance of performing static analysis on suspicious files. By thoroughly examining files, you can often identify suspicious or malicious behaviors that automated scans might miss. This approach ensures a more robust defense against threats and helps protect your organization from becoming a victim of these sophisticated attacks.


- Analyze the [Hybrid Analysis report](https://www.hybrid-analysis.com/sample/86cc510835831f1fb61d3cfbcb24f301f36d8a182bfe48a0b50640e21ffce93b/6469fa8efd2d19f45200f951).
- Answer the questions.

How many MITRE ATT&CK techniques were identified in this file?  
Ans: `37`   

What is the SHA256 hash of the file?  
Ans: `86cc510835831f1fb61d3cfbcb24f301f36d8a182bfe48a0b50640e21ffce93b`  

![Screenshot 2024-04-17 183248](https://github.com/acibojbp/RangeForce-Phishing/assets/164168280/7a13235e-17d8-4dd5-91c9-00f93ebd970e)

![Screenshot 2024-04-17 183414](https://github.com/acibojbp/RangeForce-Phishing/assets/164168280/d1652553-6944-45cc-9a19-9556c199f60a)
