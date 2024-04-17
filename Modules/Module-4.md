# Analyzing Email Contents - Attachments

You are Emmanuel Toller, a SOC Analyst at Commensurate Technology (ComTech). A suspicious email containing a potentially malicious attachment has been reported to you for analysis. This module will teach you the fundamentals of how to safely extract email attachments and analyze them both statically and dynamically to determine if they are malicious.

Learning outcomes

The learner will be able to

- safely extract potentially malicious attachments from phishing emails.
- perform static analysis on email attachments.
- perform dynamic analysis on email attachments.

## Introduction

While you will encounter various types of files that have been sent as email attachments, the three most suspicious file types to look out for are:

- **Executable** files, i.e., `.exe` (PE file type).
- **RAR** files, i.e., `.rar` (archive file type).
- **Macro enabled** Microsoft Office files, i.e., `.docm` , `.dotm` , `.xlsm` , `.pptm` , `.ppsm` . The `m` after the file type indicates that the file uses macros.
If you are unsure of what file type you are dealing with, you can look at the first bytes of the file in hexadecimal representation and refer to this [list of file signatures](https://en.wikipedia.org/wiki/List_of_file_signatures), or drop the file into [pestudio](https://www.winitor.com/). In some cases, you may need to rely on additional information provided by tools such as VirusTotal's [magic](https://docs.virustotal.com/reference/magic), which will provide a hint to help you open a file and will be displayed under the **Details** tab in **VirusTotal**. This can be particularly useful when dealing with files that have ambiguous or misleading extensions.

Although less common, certain image files like `.JPG` , `.GIF` , `.PDF` , `.TIFF` , and `.PNG` can also hold malicious code. Even if it is a cute picture of a bunny rabbit, it can still be malicious! Common social engineering techniques can be used to entice end-users to open malicious images. An example of this is the [CVE-2010-2883](https://cve.mitre.org/cgi-bin/cvename.cgi?name=cve-2010-2883) vulnerability in Adobe Reader, which allowed for remote code execution when opening a maliciously crafted PDF file.

Some questions to ask yourself when analyzing an email attachment include:

1. Does the file icon match the file type? For example, a PDF file should have the appropriate PDF icon and not an icon resembling an image file. However, it is important to note that even if the icon matches the file type, this can still be malicious as it is possible to change file icons to disguise their true nature.
2. Is the email it is attached to suspicious? Consider the origin of the email and whether it was expected or unsolicited.
3. Are there any discrepancies between the file's stated purpose and its actual function? For example, does a seemingly benign file request unnecessary permissions?

You should also be aware that phishing emails used by threat actors are becoming trickier to spot, especially when they use sneaky tactics such as embedding links within images that have been disguised to look like attachments.

![Screenshot 2024-04-17 171721](https://github.com/acibojbp/RangeForce-Phishing/assets/164168280/d6accef5-9944-49dd-9230-92ea0246329f)

When analyzing files, it is crucial that you **do not rely solely on their appearance or reputation**. Instead, you should use additional tools and techniques to verify their legitimacy. These may include community resources, decoders, and debuggers. In some cases, seeking advice from colleagues or other security experts might also be beneficial.

A great example is the [Emotet](https://en.wikipedia.org/wiki/Emotet) malware campaign. Emotet, which originated as a banking trojan, later evolved into a sophisticated delivery mechanism for other types of malware. It was primarily distributed through phishing emails containing malicious attachments, usually disguised as seemingly legitimate documents like invoices, shipping notices, or payment confirmations.

These emails often contained Microsoft Word or Excel files with embedded macros. Once the unsuspecting user opened the attachment and enabled the macros, Emotet would be executed, infecting the user's system and potentially spreading to other systems on the network. This allowed the attackers to deliver additional payloads, such as ransomware or other banking trojans, to the infected systems. This highlights the importance of thoroughly analyzing files and not relying solely on their appearance or reputation to determine their safety.

## File Extraction

Jaylee Beake, a Regional Sales Manager at ComTech, received an email from what appears to be the company's IT Support desk asking them to install a Chrome toolbar. Jaylee thinks this is suspicious and has reported it to the SOC for investigation.

Go to Outlook and open the email from Jaylee with the subject Suspicious Email. Download the attachment to the desktop so you can upload the file and its contents to various cybersecurity analysis tools. You will notice that the file has been compressed. This is a common technique used by attackers to obfuscate files. You should extract the contents of the .zip file and find out what it really is.

> Note: Before you extract the file from the email, remember that you should never open or analyze a file on a machine that is connected to the network. You should only ever analyze and run files in a sandbox environment on a host computer that you are willing to reset/wipe completely, as you could lose all content and functionality. Be careful not to accidentally open the file in your live environment. Some malware can break out of the sandbox and infect the host machine. In this instance, you may use the environment provided in this lab as your sandbox.


- Launch the Outlook web application and log in:
	 - Username: emmanuel.toller@commensuratetechnology.com
	 - Password: t0tallySecre7?
- Open the email with the subject Suspicious Email.
- Right-click on the SalesBookmarks.zip attachment and download it to the desktop.
- Extract the contents.
- Answer the question.

![Screenshot 2024-04-17 172015](https://github.com/acibojbp/RangeForce-Phishing/assets/164168280/befe19d7-e994-4304-90ed-8ab49de8df29)

![Screenshot 2024-04-17 172115](https://github.com/acibojbp/RangeForce-Phishing/assets/164168280/fae1feda-61b0-468d-aea5-5d0345873208)  

What is the file type of the contents of the zipped `SalesBookmarks` attachment?  
Ans: `.exe`

## Static Analysis

**Static analysis** refers to the process of analyzing a file without executing its code to identify any signs of malicious activity. This can involve examining a file's metadata, header information, and contents to determine if it contains any known malicious signatures, IP addresses, file hashes, or other markers associated with known security threats. The goal of this type of analysis is to quickly identify and isolate potentially malicious files to prevent any spread and minimize the risk of a security breach.

A tool that can be used for static analysis is [pestudio](https://www.winitor.com/). According to Winitor:

> The goal of pestudio is to spot artifacts of executable files in order to ease and accelerate Malware Initial Assessment. The tool is used by Computer Incident Response Teams (CIRT), Security Operations Centers (SOC) and Digital-Forensic Analysts worldwide.

Your task is to load the suspicious `SalesBookmarks.exe` file into pestudio to find the **MD5 hash** and other identifying information about the file. Gathering more information about a file will help in determining if it is malicious. You could, for example, just Google the file name, however, it would be better to search with the hash as well. A file name can be changed without changing the contents of a file, whereas a hash is distinct to that particular file and code. Thus, a single file hash can be connected to multiple file names.

Now, launch **pestudio** from the desktop shortcut and drag in or import the `SalesBookmarks.exe` file. Ensure that the tree in the left-hand pane is expanded, as shown below:

![Screenshot 2024-04-17 172252](https://github.com/acibojbp/RangeForce-Phishing/assets/164168280/c150df48-85cc-4d7b-b3ec-50ec2ec3d4aa)

The left-hand pane in pestudio typically displays the fields of information related to the **Portable Executable (PE)** file being analyzed. This may include fields such as:

- **Import Functions**: A list of imported functions from other libraries.
- **Export Functions**: A list of functions exported by the file for use by other modules.
- **Resources**: A list of resources embedded in the file, such as icons, dialog boxes, and strings.
- **Strings**: A list of **ASCII** and **Unicode** strings found in the file.
- **Sections**: A list of sections in the PE file, including their names, sizes, and permissions.
- **Headers**: Detailed information about the various headers of the PE file, such as the **DOS** header, **File** header, and **Optional** header.

You can statically analyze the information in these fields to help determine if a file is malicious, for example, if a PE file imports functions from known malicious libraries or from libraries that are not commonly used by benign files, this can be an indication of malicious behavior.

- Analyze the SalesBookmarks.exe file using pestudio.
- Answer the questions.

![Screenshot 2024-04-17 172534](https://github.com/acibojbp/RangeForce-Phishing/assets/164168280/1624d5b3-a93b-48ea-8f0d-99462809bd0e)

What is the MD5 of the file?  
Ans: `C334B788E3DA78C413364EF1E163B8FF`  

What is the first-bytes-hex of the file?  
Ans: `4D 5A 50 00 02 00 00 00 04 00 0F 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 1A 00 00 00 00 00 00`  

What is the first-bytes-hex of the file?  
Ans: `3495`  

## Dynamic Analysis

**Dynamic analysis** refers to the process of executing a file to observe its behavior and identify any signs of malicious activity. This can involve running the file in a sandboxed or isolated environment and monitoring its interactions with the system and network, including actions like **creating new processes, modifying system settings or files, sending network traffic**, and so on.

The goal of dynamic analysis is to identify malicious behavior that may not be immediately obvious through static analysis, such as the presence of malicious code that only executes under certain conditions. Dynamic analysis is often used to supplement and validate the findings of static analysis and to provide additional information about the behavior of potentially malicious files.

In the following steps, you will use online sandbox tools to perform dynamic analysis on the `SalesBookmarks.exe` file.

### VirusTotal

![Screenshot 2024-04-17 173040](https://github.com/acibojbp/RangeForce-Phishing/assets/164168280/66db8288-c304-422e-8b5f-d3daab62620f)

[VirusTotal](https://www.virustotal.com/gui/home/upload) is a free online service that analyzes files for indicators of malicious content. It uses a combination of various antivirus engines, signature-based detection techniques, and heuristics to identify security threats. VirusTotal allows users to upload a file or enter a hash for analysis, and it returns a report indicating the results of the scan. The report provides information on the number of antivirus engines that detected the file as malicious, the names of the specific engines that identified it, and any additional information or comments related to the scan. VirusTotal, which is a valuable resource for security professionals, is often used by individuals and organizations as a first step in the process of determining if a file is malicious.

You have two options when it comes to analyzing the `SalesBookmarks.exe` file in VirusTotal:

1. Upload the file manually via the Choose file button and select the file or drag the file into the VirusTotal window.
2. Click on the Search tab and search using the hash value of the file.

VirusTotal can help you determine how the security community in general judges the file, be it malicious or safe. Be aware that this is dependent upon how long the sample has been in the wild and how much investigation into the file has already taken place. If a file has been around for an entire year, there should be much more analysis on that file compared to a newly created file that has only been around for a few days.

- Go to VirusTotal.
	- Upload the SalesBookmarks.exe file or hash for analysis.
	- Examine the information in the Detection, Details, and Relations tabs.
- Answer the questions.

![Screenshot 2024-04-17 173218](https://github.com/acibojbp/RangeForce-Phishing/assets/164168280/2fe60451-c6d4-4255-b73d-e6b863f1e798)

What is the magic associated with the file?  
Ans: `PE32 executable (GUI) Intel 80386, for MS Windows`  

What is the first submission date of the file? (YYYY-MM-DD)  
Ans: `2014-04-16 02:54:55 UTC`  

What URL does the file reach out to and contact?  
Ans: `http://download.everytoolbar.co.kr/setup/everytoolbar2_setup.exe`  

![Screenshot 2024-04-17 173309](https://github.com/acibojbp/RangeForce-Phishing/assets/164168280/6cb63813-0228-4908-99db-0971fe48e735)

![Screenshot 2024-04-17 173413](https://github.com/acibojbp/RangeForce-Phishing/assets/164168280/30979091-5948-47b8-9f77-0aa63e4d9414)

### Hybrid Analysis

![Screenshot 2024-04-17 173703](https://github.com/acibojbp/RangeForce-Phishing/assets/164168280/6f410b8b-9478-475a-920e-c55ab28de2ea)

[Hybrid Analysis](https://hybrid-analysis.com/), like VirusTotal, is a free online sandbox for performing dynamic analysis of files and URLs. The website allows users to upload a file for analysis, and it executes the file in a controlled environment to observe its behavior. Hybrid Analysis then generates a report detailing the results of the analysis.

The information provided by Hybrid Analysis includes:

- **File information**: Details about the file itself, such as its size, type, and creation date, as well as information about the analysis, such as the date of the last scan and the version of the Hybrid Analysis database used.
- **System interactions**: Information about the file's interactions with the system, including the creation of new processes or files, the modification of system settings or files, and the execution of malicious code.
- **Network activity**: Information about any network traffic generated by the file, including the IP addresses and domains it communicates with and the type of traffic (HTTP, DNS, etc.).
- **Malicious behavior**: Hybrid Analysis identifies and provides information about any malicious behavior detected during the analysis, such as the presence of malware, trojans, or other malicious code.
- **Threat intelligence**: Information about the file's relationships with other files that have been analyzed, as well as any additional intelligence or information related to the file's behavior or origin.
- **Threat Score**: This can be found towards the top-right corner under a green or red rectangular box. The Threat Score is a heuristically determined value that expresses the degree of potentially malicious behavior of a file (based on static, dynamic, or hybrid runtime analysis). It is mainly based on the total relevance of all matched indicators.

This information can provide security professionals with a comprehensive view of the behavior of a file and the potential risks it poses, and can be used to make informed decisions about the file's safety and security.

> Note: Even though you have already seen the VirusTotal community consensus, Hybrid-Analysis is a different unique tool that can bring other information that may not be provided by other tools. Even if this tool just reconfirms what you already know, it is still helpful. As an example, having two witnesses corroborating information is better than having just one witness.


- Go to Hybrid Analysis.
	- Upload the SalesBookmarks.exe file and generate a public report.
	- Review the report.
- Answer the questions.

What is the file's SHA256 hash?  
Ans: `d61ec0ddcb32867e23b9e9d4e7238e98a95f78b2180fb1178aae77f6f02480dc`  

What operating system is associated with the file?  
Ans: `Windows`  

What is the IP address of the host that the malware contacts?  
Ans: `211.104.175.45`  

![Screenshot 2024-04-17 173801](https://github.com/acibojbp/RangeForce-Phishing/assets/164168280/f23df0b7-d44c-4954-86f3-343f6782c02f)

![Screenshot 2024-04-17 173954](https://github.com/acibojbp/RangeForce-Phishing/assets/164168280/b8133852-f9e3-4b0a-a74d-6f3789f71e99)
