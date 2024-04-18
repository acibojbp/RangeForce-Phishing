# Phishing Response Actions

This module will teach you the best practices for appropriately reporting and responding to phishing emails.

Learning outcomes

- The learner will be able to respond to phishing emails appropriately.

**Phishing** is a social engineering technique that aims to steal sensitive information or gain unauthorized access to systems. Phishing typically takes place over email communication and is designed to trick the recipient into believing a message is genuine, which can then lead to them clicking on a malicious link, downloading an attachment, or disclosing confidential information. Phishing attacks are often successful because they mimic legitimate communications from trusted sources, such as banks or financial institutions.

This module will teach you the best practices for appropriately reporting and responding to phishing emails.

Reporting Phishing Emails

According to **[Cisco's 2021 report](https://umbrella.cisco.com/info/2021-cyber-security-threat-trends-phishing-crypto-top-the-list)** on cybersecurity threat trends, phishing was the primary attack vector identified in breaches in 2021 and was responsible for 90% of all breaches. Phishing attacks continue to be one of the most common methods cybercriminals use to gain unauthorized access to sensitive data or compromise user accounts. As a result, all organizations and employees need to be vigilant and able to identify phishing emails when they appear in their inboxes.

Suppose an employee receives a suspicious email that they suspect to be a phishing attempt. In this case, they should immediately report the email to the organization's **Security Operations Center** (**SOC**) so that it can be investigated further and appropriate responsive actions can be taken to prevent any potential damage.

One way to report phishing emails (for organizations that use Exchange Online or on-premises mailboxes) is by using Outlook's built-in **Report > Report phishing** option, as shown in the image below. Admins can configure user-reported messages to go to a designated reporting mailbox, to Microsoft, or both. Incident responders can then use this information to update email filters, block malicious senders and URLs, and take other necessary actions to mitigate potential risks.

![Screenshot 2024-04-17 185748](https://github.com/acibojbp/RangeForce-Phishing/assets/164168280/a4a9affe-c1e9-4ed8-a02a-eb5e6aa6574d)

> **Note:** For more information on Outlook's **Report phishing** button and how to configure it, check out the **[official documentation](https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/submissions-outlook-report-messages?view=o365-worldwide)**.

Here are some guidelines for reporting a phishing email that the SOC should advise employees to follow:

1. **Do not interact with the email in any way**. Do not click on any links or download any attachments, as doing so could trigger malicious code or give the attacker access to your system.
    
2. Forward the email **as an attachment** to your organization's SOC team. This will maintain the original headers and metadata, which can provide valuable information to help the SOC team analyze the attack and determine its origin. This includes all the relevant information from the email, such as the sender's email address, subject line, and any suspicious links or attachments. Additionally, **do not forward the email to anyone other than the SOC**.
    
3. **Delete the suspicious email** from your inbox and any other folders in your email account. This ensures that you won't accidentally interact with the email in the future and eliminates the risk of it being accidentally forwarded or replied to.
    
4. If you accidentally click on a suspicious link, download an attachment, or disclose any confidential information, you should **report it to the SOC team immediately**. This information is crucial for the SOC to carry out an investigation into the incident. The SOC can also assist with resetting passwords and other necessary steps to prevent further damage.

> **Note:** Reporting suspicious emails is the responsibility of every employee. Following these best practices can help your organization avoid potential security threats and protect sensitive data.

## Mitigations

Due to the astronomical number of emails (both legitimate and malicious) that are sent every day, it is almost impossible to block 100% of the phishing messages entering the network. However, if you can identify the messages that make it through in a timely manner and take appropriate action to mitigate them, you can certainly limit the impact.

Take a look at the following phishing email received by Lorrie Hayter in ComTech's HR department:

![Screenshot 2024-04-17 185852](https://github.com/acibojbp/RangeForce-Phishing/assets/164168280/62559d2a-ec9f-41af-90c3-636dbd28c31c)

You don't need to be a security expert to identify some of the suspicious elements of this email. However, you can also see how it would easily fool some recipients — and for opportunistic threat actors, that is good enough.

Lorrie was one of several ComTech employees who received the email. Unfortunately, Lorrie was also the one who fell victim to this phishing attack, and as a result, provided her credentials to the attacker. In the following steps, you will explore some of the appropriate response actions that the SOC should take in this case...

> **Note:** The response actions outlined in this module are not an exhaustive list. Depending on the specific circumstances of a phishing incident, additional response actions, such as malware containment and recovery procedures, may be necessary. Following your organization's **Incident Response** (**IR**) plan is important when responding to a security incident as every organization operates differently.


### Purging Phishing Emails

As a SOC analyst, you have investigated the mail audit logs and found that the email was sent to five ComTech employees. Only two of the five recipients have opened it — the user who reported it to you and Lorrie.

To prevent further compromise, it would be best to remove the email from the other three users' inboxes before they open it. The **MITRE D3FEND** technique **[Email Removal](https://d3fend.mitre.org/technique/d3f:EmailRemoval/)** is a defensive countermeasure that involves deleting email files from system storage, which helps prevent users from executing malware or replying to phishing attempts.

Once a phishing email has been identified and reported to the SOC, it's essential to take immediate action to prevent any additional damage. Purging the malicious email from all inboxes is the first step in mitigating the impact of a phishing attack. By removing the email, you can reduce the risk of it being accidentally opened or replied to, and prevent it from spreading to other users in the organization.

To purge the phishing email from inboxes, administrators can use a search tool, such as **Exchange Online** in Microsoft 365, to search for the phishing email by **sender**, **subject**, or any other relevant criteria, and then delete it from all inboxes. Additionally, it is essential that users are informed about the phishing email and the steps that can be taken to remove it from their inboxes. Administrators can deliver this vital information via internal communications, such as a company-wide email or an announcement on the company's **instant messaging** (**IM**) solution.

**Note:** Microsoft provides detailed documentation on how to purge unwanted emails from user inboxes. You can find it **[here](https://learn.microsoft.com/en-us/microsoft-365/compliance/search-for-and-delete-messages-in-your-organization?view=o365-worldwide)**.


### Account Remediation

Now that it's clear that only Lorrie's account may have been compromised, the next step would be to ensure that the account is remediated. The D3FEND technique **[Credential Eviction](https://d3fend.mitre.org/technique/d3f:CredentialEviction/)** is a defensive countermeasure that includes sub-techniques for disabling or removing compromised credentials from a computer network.

You should follow the best practices for detecting and blocking a compromised account after a phishing attack. The goal is to prevent further damage and minimize the impact of the attack.

Typically, the first step after a successful phishing attack is to identify the compromised accounts. You can determine which accounts have been compromised by analyzing the phishing email and any relevant information it provides. In this module's example, the email was sent to five ComTech employees and contained a malicious URL to a credential-thieving site. You could ask the recipients if they entered any credentials into the site and check the logs related to their account or machine activity to see if they visited the site. This information can help you determine which account was compromised and how the attacker gained access.

A compromised account is a significant security risk that must be dealt with promptly. In this case, the user informed you that they fell for the social engineering tactics and provided their credentials to the attacker, thinking it was a legitimate request from Microsoft. In most real-life scenarios like this one, it's likely that the user wouldn't even realize their mistake and would continue none the wiser.

For this reason, it is important to be aware of some other indicators of a compromised email account, including:

- **Suspicious activity**: Such as logins from unexpected locations or changes to sensitive information.
- **Suspicious or unusual emails**: Emails sent from the compromised account to others in the organization, such as emails requesting sensitive information or containing malware.

Once the compromised account has been identified, the attacker's access to the account must be revoked. Here are the steps to revoking access and restoring a compromised account:

1. **Lock or disable the compromised user account**. This will disrupt the attack by essentially disabling the account. Suppose a domain admin account was compromised, the attacker could then create new accounts and add them to certain groups for persistence and lateral movement. Therefore, it is important to disable the compromised account, remove it from any groups or teams, and disable any access to sensitive information.
2. **Reset the account password**, ensuring that it is strong and follows the organization's password policy.
3. **Monitor the account** for any suspicious activity by reviewing logs, monitoring for any attempts to log in, or reviewing any emails sent from the account.
4. **Inform the account owner** of the compromise and provide guidance on steps they can take to secure their account, such as resetting passwords for any linked accounts, enabling two-factor authentication, and staying vigilant for any suspicious emails or activity. In addition, if the user was a victim of a social engineering tactic, providing additional security awareness training to the user and other employees may also be beneficial.

**Note:** **[HaveIBeenPwned](https://haveibeenpwned.com/)** is a valuable tool that allows you to check if an email address has been involved in a data breach. The website, which is free to use, provides information on the breach and what type of data was compromised, allowing you to better understand the scope of the compromise and take additional steps to secure the account. It's a good idea to regularly check if any of your organization's accounts have been involved in a data breach.

## Crafting Phishing Rules

Once a phishing email has been purged from all recipients' inboxes and any compromised accounts have been restored, the next step would be to craft a rule that will help prevent similar emails from reaching end users in the future.

As a SOC analyst, you can use the following components of the phishing email's header or body to create a phishing rule:

- **Sender's email address or domain**: This can be used to block emails from specific email addresses or domains. For example, if the phishing email was sent from a spoofed sender that appears to be from a trusted entity, you can block all emails from that specific address or domain.
- **IP address**: If the phishing email was sent from a specific IP address, you could use this information to block emails from that IP address or IP range.
- **URLs or attachments**: If the phishing email contains a malicious URL or attachment, you can use this information to block emails with the same URL or attachment.
- **Subject line or body text**: You can also use the phishing email's subject line or body text to create a rule. For example, if the phishing email contained specific keywords or phrases commonly used in phishing attacks, you can create a rule that blocks emails containing those.

Take another look at the email you saw previously:

![Screenshot 2024-04-17 190033](https://github.com/acibojbp/RangeForce-Phishing/assets/164168280/fec73e7f-b590-42e0-afad-90dd5e2feb14)

You could use the following components of the example email to craft detection rules like so:

1. **Sender's address**: The sender's email address appears to be from the Microsoft account team, however, the actual email address is an attempt at **[masquerading](https://attack.mitre.org/techniques/T1036/)**. You can block emails from the sender's email address, however, you probably don't want to block the entire domain in this case as it is simply an Outlook address.
2. **Malicious URL**: The URL in the body of the email is malicious and leads to a phishing site. You could create a rule to block emails containing this URL. It would also be a good idea to block access to the URL on the web filter.
3. **Subject and body text**: The subject line and body text of the email contain specific key phrases, for example, **verify your account**, which are commonly used in phishing attacks. The analyst can create a rule that blocks emails containing these keywords. You should be careful with this approach, however, as this could produce some false positives — and blocking legitimate messages is not good practice. You should also be aware that malicious actors sometimes use the same language that is found in legitimate correspondence when crafting targeted spear phishing emails.

Using the elements of the phishing email header or body, you can craft effective phishing rules that will help prevent similar malicious emails from reaching end users. It's important to regularly review and update the phishing rules to ensure that they remain effective against the latest phishing tactics and technologies.


- Answer the questions.
  
What advice should the SOC give to employees for reporting a suspected phishing email?

Investigate the email further to confirm that it is malicious before reporting it.  
**Forward the email as an attachment to the SOC.**  
Forward the email to the SOC.  
Reply to the email and CC the SOC.  

Why is it essential to remove a phishing email from all email inboxes after it has been reported to the SOC?  

**To prevent users from interacting with the email in any way.**  
To analyze the email headers and metadata to determine its origin.  
To move the phishing email to a separate folder in the user's inbox so that they can refer to it later.  
To mark it as malicious to prevent future similar emails from being delivered.  


What is the first step in revoking access to a compromised account?  

**Lock/disable the compromised user account.**  
Reset the account password.  
Inform the account owner about the compromise.  
Monitor the account for suspicious activity.  

What specific components of an email's header or body can be used to create an effective phishing rule? (Select all that apply.)  

Recipient's email address  
**Sender's email address or domain**  
**Body text**  
The date the email was sent  
**Attachments**  
**Subject line**  
**Sender's IP address**  
