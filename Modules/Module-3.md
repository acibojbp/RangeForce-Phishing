# Analyzing Email Contents - URLs

In this module, you will learn how to safely extract URLs from emails and analyze them using the OSINT (open-source intelligence) tool called urlscan.io.

Learning outcomes

Upon completion of this module, learners will be able to

- Safely extract potentially malicious URLs from phishing emails.
- Use **urlscan.io** to analyze URLs and derive a threat reputation score from the link.

You have already been exposed to various phishing emails by now and should have the ability to spot a suspicious email when you see one. Unfortunately, it's not always that easy.

In this module, you will take on the role of Quidel Aiken, an Information Security Intern at Commensurate Technology, and learn how to treat, export, and analyze the URLs (Uniform Resource Locators) in your mailbox without causing any harm to your workstation.

## Contents
- [Best Practices](#best-practices)
- [URL Investigation](#url-investigation)
- [URL Scanner](#url-scanner)

## Best Practices

Despite Awareness and Cyber Hygiene training, people are still falling victim to phishing attacks. The question is, why?

Cybercriminals often focus on benefiting from human negligence. People are inevitably going to make mistakes, but this negligence can cost millions of dollars worth of data breaches. In fact, [Ponemon Institute's](https://www.ponemon.org/) **2020 Cost of Data Breach Study** found that:

> The global average for a data breach is $3.83 million, but the average cost of a data breach in the United States has hit an all-time high of $8.64 million.

In this module, you will focus solely on the URLs inside incoming mail messages.

Note: The first order of email security is that you should **never** click on a link in an email if you are at all suspicious. This applies to all your devices — personal computers, laptops, and smartphones.
Clicking on malicious links can lead to the immediate compromise of your account and even your workstation. Depending on the exploit, attackers can:

- Deceive you to enter plain-text credentials.
- Dump password hashes from your workstation.
- Steal your digital fingerprint that consists of IP address, MAC address, device information, and Web-browser plugins.

These are pretty significant risks. Fortunately, there are ways to protect yourself and your devices, such as:

- Online scanning services (e.g., urlscan.io and virustotal.com).
- Virtual sandboxes (e.g., VMware, VirtualBox, and Qubes OS).
- Administration tools (e.g., Sysmon, Process Explorer, and Wireshark).

> Note: Bear in mind that malware may detect a virtual environment and not start inside a sandbox.

Which method complies with the best practices for the extraction of suspicious URLs from emails?  

Update your OS and open links from your smartphone.  
**Extract links from the email's source code and run them inside a sandbox.**  
It is safe to open any links as long as my anti-virus is enabled.  
Forward it to your colleague and ask to check the link.  


## URL Investigation

Julyan Beringer, a Finance Intern at Commensurate Technology, has just received an email from what appears to be the company's IT Support desk explaining that his password is about to expire. Is the email really from who it claims to be? Launch Outlook on the web and take a closer look.

![Screenshot 2024-04-17 164417](https://github.com/acibojbp/RangeForce-Phishing/assets/164168280/4a49d44e-4e84-4111-9887-9aa0ab10c643)

The suspicious email contains a link to a URL. However, Julyan is hesitant to click on this link after noticing that the sender is not who they appear to be. Instead, he has reported this email to the security team for further investigation.

> Note: Just a reminder that you should never click on a link in an email if you are at all suspicious.

It appears that the attacker has embedded a malicious URL inside a seemingly legitimate link. This is a technique used by attackers to hide the actual URL in the hope that the recipient clicks the link.

You can see the embedded URL if you view the email in its HTML format. This is a safe way to extract any embedded URLs as it is pretty easy to accidentally click on the malicious link when trying to do this in the email body.

To download the attached email and open it in HTML format, click Download and open it with a text editor of your choice (e.g., Notepad).

> Note: Your browser might complain about the maliciousness of the .eml file. Press Keep to download it on the Windows 10 workstation.

![Screenshot 2024-04-17 141529](https://github.com/acibojbp/RangeForce-Phishing/assets/164168280/8e6187cd-69c3-488e-ba77-27d94d9d7d8c)

- Launch the Outlook web email client.
  - URL: https://mail.commensuratetechnology.com/owa
  - User: Quidel.Aiken@commensuratetechnology.com
  - Password: Doma1nUs3r!
- Download and analyze forwarded.eml.
- Answer the questions.

![Screenshot 2024-04-17 164907](https://github.com/acibojbp/RangeForce-Phishing/assets/164168280/4cc3c546-ee61-42a1-8d09-4fdca0f5601f)

What is the actual URL of the embedded link?  
Ans: `http://big-0cad8d00-ip-3843-4f68-9764-score-b243b4457d97.ru`  

What Content Transfer Encoding method is being used for the attachment? (Look under the body section of the headers.)  
Ans: `base64`  

## URL Scanner

**urlscan.io** is an open-source intelligence (OSINT) tool used by security professionals to scan and analyze websites without the need to visit the site. When a URL is scanned by urlscan.io, an automated process will navigate to the URL just like a regular user and record the page navigation activity. This includes the domains and IP addresses contacted, the resources requested from those domains, e.g., JavaScript and CSS, and any additional information about the page itself. Additionally, urlscan.io will also take a screenshot of the page so you can see the contents/layout without putting yourself and your machine at risk.

Here is an example of a scan report of a URL that has been flagged as **Potentially Malicious** by urlscan.io:

![Screenshot 2024-04-17 141901](https://github.com/acibojbp/RangeForce-Phishing/assets/164168280/7f29dedd-bdf3-45bd-990d-9e28a91bec66)

As you can see, some key information can be taken from this report, such as the IP address used by the site, the brand it's targeting, the classification provided by urlscan.io, and also a screenshot of the malicious site. In this case, the site is mimicking a Yahoo login page in an attempt to steal victims credentials:

![Screenshot 2024-04-17 141917](https://github.com/acibojbp/RangeForce-Phishing/assets/164168280/1bef1dbd-842b-4f90-9eab-ea744c808660)

Now, find out what urlscan.io says about the URL found in Julyan's phishing email. Submit the suspicious URL from the previous step to urlscan.io and see what it returns.

![Screenshot 2024-04-17 141947](https://github.com/acibojbp/RangeForce-Phishing/assets/164168280/3392f1c7-f256-4717-bad3-9601a12bac4c)  

![Screenshot 2024-04-17 142001](https://github.com/acibojbp/RangeForce-Phishing/assets/164168280/42922a8e-d041-44d4-9948-58ee58fed4af)

What Verdict classification has urlscan.io given the scanned URL?  
Ans: `Potentially Malicious`  

Which popular brand is the malicious site trying to mimic?  
Ans: `Google`  

What is the main IP address used by the malicious site?  
Ans: `173.187.75.238`  
