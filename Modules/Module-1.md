# Types of Phishing Emails and Techniques

This module covers the standard indicators for identifying a phishing email. You will learn about the different types of phishing emails and the various techniques utilized by threat actors.

Learning outcomes

Upon completion of this module, learners will

- Know the types of phishing emails.
- Know the different phishing techniques employed by threat actors.
- Understand how phishing can be used as an attack vector, including what it can lead to and the impact of a successful phishing campaign on an organization.

## Contents
- [Examples of Phishing Emails](#examples-of-phishing-emails)  
- [Phishing Techniques](#phishing-techniques)  
- [Typical Phishing Process](#typical-phishing-process)  
- [Social Engineering](#social-engineering)  
- [Link Manipulation](#link-manipulation)  

## Examples of Phishing Emails

**Phishing** is a **social engineering technique** that attempts to steal information from unsuspecting victims. Phishing attacks typically happen over email communication. A phishing attack aims to trick the email recipient into believing that the message is genuine, resulting in them clicking a malicious link or disclosing sensitive information. Phishing attacks are often successful because they mimic legitimate communications from trusted entities, such as fraudulent emails from a bank. According to [CISCO's 2021 Cybersecurity threat trends report](https://umbrella.cisco.com/info/2021-cyber-security-threat-trends-phishing-crypto-top-the-list), phishing is the primary attack vector seen in breaches in the last year and is responsible for 90% of all breaches.

There are various types of phishing, two of the most common include:

- **Spear phishing**: The attacker targets a specific type of individual or group, such as an organization's system administrator. The attacker knows precisely whom they are targeting and what they want from them.
- **Whaling**: A more targeted attack where the attacker targets high-profile employees like the CEO, CFO, or any big players in an organization. The general goal of these attacks is to manipulate the victim into setting up high-value transfers to the attacker. The name whaling tends to compare the size of the attack in reference to a whale because typically, the victim is of high profile. A whaling attack is usually difficult to detect and prevent. However, the security team can help by keeping all staff well educated on security awareness.

## Phishing Techniques

There are a couple of phishing techniques that you should be aware of. The main tactics associated with phishing are **Reconnaissance** and **Initial Access**.

![Screenshot 2024-04-17 142406](https://github.com/acibojbp/RangeForce-Phishing/assets/164168280/ac0e517f-d3ec-4c8e-84df-8335ac71dc73)

**[Phishing for Information (T1598)](https://attack.mitre.org/techniques/T1598/)** - Attackers may use many techniques to gain reconnaissance — this is the stage in which they gather as much information about the victim as possible to make the attack effective. In the case of phishing, this may start from the content included in the phishing email. The attacker should know enough about the victim to include relevant material to ensure that the victim will be interested in the email.

An example of reconnaissance that malicious actors have carried out is when **[Dragonfly](https://www.secureworks.com/research/resurgent-iron-liberty-targeting-energy-sector)** used spearphishing campaigns to steal the credentials of their victims with a spearphishing email in 2017.

**[Phishing (T1566)](https://attack.mitre.org/techniques/T1566/)** - Initial access is established via phishing and is how the attacker gains access to the targeted system. An email is sent to the victim containing a malicious link, which will execute malicious code onto their machine/system when clicked.

The idea is to lure the victim in; therefore, the attacker will imitate someone who would usually be trusted, a used organization, for example, and who requires additional information from the customer targeted as a victim. The attacker will then prompt the victim to supply this information, providing a malicious link, image, URL, or however they choose the display it. Attackers usually make the email appear urgent, possibly requiring an update of a payment method or email address — something that may worry the victim and convince them to act rashly.

An example of initial access that malicious actors have carried out is a threat group, **[APT28](https://blogs.microsoft.com/on-the-issues/2020/09/10/cyberattacks-us-elections-trump-biden/)**, who used spearfishing to compromise the credentials of their victims.

## Typical Phishing Process

An example of a typical phishing attack is as follows:

![Screenshot 2024-04-17 142427](https://github.com/acibojbp/RangeForce-Phishing/assets/164168280/c682e790-8a67-4acb-9111-87fe5954d443)

**1.** The threat actor uses **OSINT** (Open Source Intelligence) to gather information about the target, helping them conduct a luring email. Attackers often find information about their targets via the following sources:

- Target organization's website
- LinkedIn
- Google
- etc.

**2.** A malicious payload is created or purchased from a malware-as-a-service provider.

**3.** A convincing phishing email is constructed based on the information gathered by the attacker in step one. Attackers often use social engineering techniques to make the target do what they want. For example, they may try to convey a sense of urgency. The malicious payload will also be included in the email, typically embedded in a seemingly legitimate document or link.

**4.** The phishing email is then sent to the target(s).

**5.** The target receives the email and clicks the malicious link or opens the malicious attachment.

**6.** The malicious payload is downloaded and executed on the target machine.

**7.** Backdoor access is established. This provides the attacker with access to the system, which they can use to:

- Execute malicious code.
- Exfiltrate data.
- Escalate privileges.
- Move laterally across the network.

## Social Engineering

**Social Engineering** refers to various malicious activities that an attacker can carry out where they manipulate victims into sharing personal or sensitive information. The process can be broken into several steps and is known as the **social engineering lifecycle**. This involves the attacker investigating the victim, finding a possible method of gaining entry, and identifying any security flaws in the system that would allow for the attack to occur. Once this information has been gathered, the threat actor will try to gain the victim's trust to enable them to break into the system. An example of this would be threat actors gaining passwords to grant themselves access to some critical resources.

One of the most critical elements of an email-based phishing attack is undoubtedly the email itself. Phishing emails have constantly been evolving as technology advances and security awareness increases. However, phishing emails mimic two different types of entities:

- **Humans**: Emails that mimic humans often pretend to be clients, employees, or leaders of the targeted company. While being quite flexible, effective execution requires a more significant deal of insight into the company's HR and work culture.
- **Robots**: Emails that mimic robots usually pretend to be automated no-reply messages from a service or platform the targeted company is using. These attacks are often easier to perform due to the universally equivalent emails and login pages of industry-standard software.

Phishing is all about taking advantage of people's psychology. Crafting convincing phishing emails is an art in itself and is heavily dependant on the context of the target. However, there are some generic tactics used by threat actors to keep in mind:

- **Urgency**: Using language that conveys the urgency of a situation will undermine proper assessment and pressure the subject to act as instructed (falling for the attack).
- **Authority**: People tend to follow experts and highly informed individuals. Attackers exploit this human tendency to suppress doubts in instructions that would otherwise be considered unusual. Consequently, many phishing emails impersonate CEOs and IT experts.
- **Scarcity**: Humans tend to value resources or opportunities more when they are scarce. One example of using this psychological trait as an advantage is imitating an automated warning, such as "Your account will be deactivated in 24 hours unless you sign in!" Another example is offering a bonus for the first 100 people who complete a (malicious) HR survey.
- **Curiosity**: People often open links or attachments simply because they are curious. An attacker may abuse this behavior by warning about the confidentiality of the information or hinting that it might be embarrassing to someone, usually the victim.
- **Inconvenience**: Most people do not like to waste their time dealing with a failed bank transfer and would prefer to get it sorted immediately. Attackers sometimes craft emails that inform the victim of an error with an important process. Not wanting to waste any time, the victim will open the link to see what's wrong.


When it comes to social engineering via phishing, the typical attacker generally operates in a sequence, which has been illustrated below.

The four stages of the social engineering lifecycle are as follows:

![Screenshot 2024-04-17 142445](https://github.com/acibojbp/RangeForce-Phishing/assets/164168280/9bf8d272-8f63-4973-85f5-b9069270b151)

- **Research**: Gather information on the victims. Find out their weaknesses and decide on the chosen attack type.
- **Hook**: Get the victim's attention, manipulate them into believing the attacker is providing them with something they are not.
- **Play**: The victims' information is extracted, and the attack is executed to misuse the stolen data.
- **Exit:** Interaction has ended, and the attacker leaves without any trace where possible by removing malware and covering tracks.

A phishing attack that uses social engineering is solely based on human error rather than weak security. Therefore, it is slightly more challenging to determine how successful these attacks are as every human is different, and the attacker relies on the victim falling for their tackle.

## Link Manipulation

Phishing scams are link-based manipulation, where the intention is to manipulate the victim into clicking on a malicious link. The link is usually camouflaged in some way so that the victim assumes it is legitimate. User input is embedded into the path or domain of the URL, generally appearing in application responses. So, when the victim clicks on the URL, the response will modify the target of URLs.

There are a few ways the attacker can incorporate malicious links into emails for their victims:

- **Hiding URLs**: URLs can be hidden within the text. For example, instead of showing the actual URL, they can use clickable words, like **"[Unsubscribe]()"**, or **"Click [here]() to update your payment details"**. This can also be used to hide malicious URLs that are typically misspelled — the attacker would insert the posing URL as the placeholder for the malicious URL so that everything looks legit. Once the user clicks on any of the above links, they will have been phished.
    
- **Links embedded in images**: Victims can be manipulated using images, where all it takes is one click of an image for the user's system to be infected. A file attachment on an email will always increase the risk of it being malicious. Something that is becoming increasingly common is an image disguised as a file attachment that points to a malicious URL. The following image is an example of how this looks:

![Screenshot 2024-04-17 142602](https://github.com/acibojbp/RangeForce-Phishing/assets/164168280/778dddf0-39f4-41cb-b221-aa43fae9150a)

_The above shows a phishing email with an image disguised as an attachment, with an embedded URL to a malicious site._

**Note:** You can always check for embedded links by viewing the email source, which will show the email in HTML format.

- **IDN spoofing**: Internalized Domain Name spoofing is when the victim is led to believe that they are on a genuine website when in fact, it is a copy created for malicious purposes. The domains used will often be almost identical, with a letter misplaced or an underscore. Something minor enough to be convincing at a glance. This is usually done by replacing certain letters with characters of similar visual aspects, for example, `0` and `O` .

- **Open URL redirectors:** These are often used to take the victim to the redirected website. The victim will click on a link thinking it is site X, when in fact, it is a malicious site hosted by the attacker for malicious purposes. An example of a basic URL redirector is `https://www.rangeforce.com/?redirect=http://www.phishingwebsite.com` . While it is evident that this link is malicious, the attacker could create a long URL to help hide the obvious redirector, meaning it would be less obvious to the victim.

---

Most organizations try to keep employees educated on the danger of clicking on unknown links and phishing emails in general. However, it is not always enough as malicious actors are becoming increasingly talented, and attacks look more convincing than ever.

Here are some tips that may be useful to help protect your organization against phishing emails:

- Inspect the email. What does it say? Does it contain any URLs, attachments, or embedded messages? Is the sender someone you've dealt with before?
- Use OSINT tools to flag up any suspicious addresses. Most legitimate organizations have their domains and wouldn't be using a regular email provider. However, if the domain is one you don't recognize, there are sites out there that let you check domains and find out if they are on a blocklist
- If you have any suspicions, do not open the link unless on a clean, isolated machine that has been set up for these purposes only.
- Another typical spotter is the **From** and **Reply-To** or **Return-Path** headers not matching. An email may be spoofed to look like it's coming from a legitimate source, but when you inspect the headers, it will show the actual sender's email address.

---

A threat actor sends an email to the CEO of Comtech. Their goal is to manipulate the CEO into transferring a large sum of money to them. What type of phishing attack is this?  
- Phishing  
- Spearphishing  
- **Whaling**  
- CEO Fraud  

In which stage of the social engineering lifecycle would the malicious attacker execute the attack?  
**Play**  

In which stage of the social engineering lifecycle would the malicious attacker engage and manipulate the victim?  
**Hook**  

How can you protect yourself from link manipulation? (Select 4)  
- **Inspect the email contents for suspicious links.**  
- Go to the URL and check if it's trying to steal credentials.  
- **Check that the sender's email address is legitimate.**  
- Open the attachment and look for malicious links.  
- **Inspect the email headers.**  
- **Check if the senders domain is on a blocklist.**  

Phishing attacks can be associated with which which MITRE ATT&CK **tactics**? (Select 2)  
- **Reconnaissance**  
- Resource Development  
- **Initial Access**  
- Execution  
- Persistence  
- Privilege Escalation  

You receive an email from Microsoft saying that your password has expired. There is a link to reset your password. When you check the URL it shows: `rnicrosoft.com` . What type of **link manipulation** is this?  
- Hidden URL  
- **IDN spoofing**  
- Open URL redirector  
