# Analyzing Email Headers

In this module, you will learn how emails are structured in their raw original format and perform analysis on email headers.

Learning outcomes

The learner will be able to

- Recognize important information that is stored within email headers.
- Analyze email headers.

Every email you send or receive on the internet contains a header consisting of meta-data that can be helpful in routing, filtering, and analyzing emails.

Get ready to take on the role of Quidel Aiken, an Information Security Intern at Commensurate Technology, who deals with email threats on a daily basis. In this role, you will learn how emails are structured in their raw original format and how to perform analysis on email headers.

## Contents
- [Email Structure](#email-structure)
- [MXToolbox](#mxtoolbox)
- [AbuseIPDB](#abuseipdb)

## Email Structure

Everybody knows what emails are. If you work in a corporate environment, you probably send and receive hundreds of them daily. In fact, in 2020, there were over 300 billion emails sent per day worldwide. But are you aware of the components that make up an email?

All emails consist of three main components:

Envelope: This is similar to a physical envelope as it contains the To/From information and the "letter" inside. Mail clients/servers use this information to send and receive said emails using the Simple Mail Transfer Protocol (SMTP).
Header: Once received, the mail client only shows the letter, which comprises the header and the body of the message. The header contains metadata about the message, such as the sender's name and email, the date it was created, and the subject. You can read more about the structure of email headers here.
Body: This is the actual content of the message contained in the email — and the part you most likely focus on every day.

![Screenshot 2024-04-17 160755](https://github.com/acibojbp/RangeForce-Phishing/assets/164168280/5c0aa858-6a3a-484a-8485-9d06a98ee931)

As previously mentioned, the envelope contains the To/From information required for sending and receiving emails over SMTP. The letter's content isn't used at all for this, which means that anything can be written in there without it affecting how the email is delivered.

SMTP communication works by sending commands between the client and the server. One of these commands is the MAIL FROM command, which determines the sender's email address. Unfortunately, it is quite easy to specify a fake email address in the MAIL FROM command — this is also known as spoofing. Attackers use this spoofing technique to trick victims into thinking that the email is legitimate as it looks to be from a trusted source, such as a supplier, a colleague, or even their boss.

Fortunately, there is a way to check if an email address has been spoofed — by analyzing the Received headers. These are the most reliable as they list all the servers/computers through which the email traveled to reach its destination.

Now, take a look at the headers of a legitimate email sent from the IT Support Desk at ComTech.

Note: Be aware that it is also possible for attackers to spoof the address displayed in the headers. However, it is a little bit trickier, and the common opportunistic attackers will often overlook this.

- Launch the Outlook for Web (OWA) email client.
  - URL: https://mail.commensuratetechnology.com/owa
  - User: Quidel.Aiken@commensuratetechnology.com
  - Password: Doma1nUs3r!
- Open the Phishing Awareness Email.
  - Go to More actions > View message details to see the header.
- Answer the question below.

![Screenshot 2024-04-17 140432](https://github.com/acibojbp/RangeForce-Phishing/assets/164168280/e0363c12-b870-4bc1-8638-a5501285e5ea)  

![Screenshot 2024-04-17 161740](https://github.com/acibojbp/RangeForce-Phishing/assets/164168280/7924fa98-86b9-41af-8556-c5a72e4b2515)

What is one of the IP addresses that the email was received from?  
Ans: **172.16.1.6**


## MXToolbox

As you may have noticed, it's not exactly easy to read the information displayed in email headers. Thankfully, there is a tool you can use to make the information more human-readable. [MXToolbox](https://mxtoolbox.com/), a provider of free blocklist, DNS, and email tools, is used by security professionals to monitor and analyze server systems. MXToolbox includes an **Email Header Analyzer** where you can upload headers and review the contents in a human-readable format. This provides useful diagnostic information such as hop delays, anti-spam results, and more.

Firstly, you need to open MXToolbox's [Email Header Analyzer](https://mxtoolbox.com/EmailHeaders.aspx) and paste in your header, as shown below.

Here are some notable headers to pay attention to:

**Reply-To**: This is used to specify the recipient when you reply to the email. If it is different from what's originally shown on the screen, you may accidentally send your reply to someone else. The other thing to keep your eye on is the `Return-Path` . This is used when an email cannot be delivered to its recipients, and it **bounces back**. Spammers don't want all the undelivered emails to end up in their inboxes.

**Received**: Shows the trail of an email message from the sender to its recipient. The origin is listed at the bottom and each server adds its header entries to the top of the email body. The example below describes the delivery of the message from `SENDER` to `RECIPIENT` with one stop at `TRANSFER-SERVER`.

```
Received: TRANSFER-SERVER ([SERVER-IP])
    (envelope-from <SENDER>)
    for <RECIPIENT>; Sun, 1 Dec 2020 01:15:00 +0000
Received: from SENDER-HOSTNAME (unknown [SENDER-IP]
        TRANSFER-SERVER
    for <RECIPIENT>; Sun, 1 Dec 2020 01:01:00 +0000
```

Google has an [online tool](https://toolbox.googleapps.com/apps/messageheader/) that helps to examine the `Received` headers and the time delay between them. Large delays in accepting an email by the first server may be a **sign of overloaded and resource-constrained spam servers**. Usually, it only takes a few seconds to transfer an email.

- **Attachments**: Sometimes unexpected attachments may appear in your correspondence, or the **MIME-type (Multipurpose Internet Mail Extensions)** of the attachment may be different than you expect. Obviously, when you are expecting a PDF attachment but its MIME-type is `application-x-msdos-program` , this is a sign of possible malicious activity. For your own research, take a look at this table by MetaFlows on the [Worst MIME Types](https://web.archive.org/web/20220216210602/https://research.metaflows.com/stats//worst_mime_types/).

- **Authentication**: **SPF**, **DKIM**, and **DMARC** are ways to authenticate your mail server and to prove to ISPs, mail services, and other receiving mail servers that senders are truly authorized to send emails. When properly set up, all three prove that the sender is legitimate.

- **SPF (Sender Policy Framework)**: An email authentication method that specifies which IP addresses and/or servers are allowed to send emails from that particular domain. The list of authorized sending hosts and IP addresses is published in the DNS TXT record for that domain.

- **DKIM (DomainKeys Identified Mail)**: Also known as **email signing**. This validates the authenticity of email messages. Every email is signed with a private key when it's sent out and that signature is validated by the receiving email server or the internet service provider. The goal is to prove that the integrity of an email message has not been affected — that neither the message itself nor its headers have been tampered with.

- **DMARC (Domain-based Message Authentication, Reporting, and Conformance)**: Confirms that a sender's email messages are protected by both SPF and DKIM. If the messages don't pass the check, they can either be delivered, quarantined, or rejected, depending on instructions within DMARC records.

You should also pay attention to **server-specific headers**, which are checking whether the email has been authenticated in a trustworthy way for the mailing server. Since you are going to deal with the **Exchange Server 2013** in this module, the authentication headers may differ from the usual SMTP headers.

`X-MS-Exchange-Organization-Network-Message-Id` : Generated by the sending mail system the identifier of emails. This identifier is not always unique. Multiple copies of the same message in multiple folders or mailboxes might have the same Message-ID.  
`X-MS-Exchange-Organization-AuthSource` : A fully qualified domain name (FQDN) of the server that evaluated the authentication of the email.  
`X-MS-Exchange-Organization-AuthAs` : Specifies the authentication source. The possible values are *Anonymous*, *Internal*, *External*, or *Partner.  
`X-MS-Exchange-Organization-AuthMechanism` : Specifies the authentication mechanism, the value is a 2-digit hexadecimal number. Unfortunately, Microsoft doesn't publish any documentation on `AuthMechanism` identifiers and its functionality.  

- Use MXToolbox to analyze the headers from the URGENT Favor email.
- Answer the question below.

![Screenshot 2024-04-17 134324](https://github.com/acibojbp/RangeForce-Phishing/assets/164168280/9e0ac3af-05da-4e2d-b8a5-784607c1afab)  

![Screenshot 2024-04-17 134538](https://github.com/acibojbp/RangeForce-Phishing/assets/164168280/da6f08be-389e-4c51-82d1-252b507bda44)



What is the Reply-To path in the URGENT Favor email?  
Ans: `malicious.sender@supermaliciousdomain.com`

## AbuseIPDB

Reading and understanding email headers is a necessary skill for email security. You can strengthen your security with free services, for example, by running suspicious attachments through VirusTotal's sandbox or utilizing open-source intelligence on malicious actors.

For this objective, you are going to use [AbuseIPDB](https://www.abuseipdb.com/) to look up the sender's IP address for malicious records. AbuseIPDB is a free repository for webmasters, system administrators, and other interested parties to report and identify IP addresses that have been associated with malicious activity online. So, you simply have to find the IP address in your headers or network logs and search for it using AbuseIPDB.


As you can see from the body of the Action Required - Hallam Bullock email, your colleague has received a suspicious-looking email. Hallam has downloaded the source code of the message and forwarded it to you as an attachment to the email. Download the attachment and analyze the Sender IP address.

- Download the suspicious.eml attachment in the Action Required - Hallam Bullock email.
- Analyze the Sender IP address with AbuseIPDB.
- Answer the questions below.

![Screenshot 2024-04-17 134807](https://github.com/acibojbp/RangeForce-Phishing/assets/164168280/dd2a19e9-20a6-486c-bbd8-9c001961a0b2)

![Screenshot 2024-04-17 135632](https://github.com/acibojbp/RangeForce-Phishing/assets/164168280/26f00a55-a78b-45c5-a060-ec037b6c60cb)  

![Screenshot 2024-04-17 135033](https://github.com/acibojbp/RangeForce-Phishing/assets/164168280/734160e1-35c7-4f18-b6b0-4426e9763ba2)  

What is the SPF value in Authentication-Results? (Expected format: spf=value)  
Ans: **spf=none**
 
What is the Sender IP address found in the suspicious.eml attachment?  
Ans: **165.154.225.110**

What is AbuseIPDB's Confidence of Abuse for the Sender IP?  
Ans: **0**
