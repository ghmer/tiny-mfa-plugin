# tiny-mfa-plugin
After some time of hacking, here is the tiny-multifactor-authentication plugin for IdentityIQ!
It will provide you with a (very, very) basic interface for enrolling MFA with IdentityIQ.

## Why is there a need for such a plugin?
There is absolutely no need for this plugin! This was created as part of the new MFA capabilities of SailPoint IdentityIQ 7.2. As I didn't own a multifactor-authentication server and also was kinda interested in how this stuff works, I decided to build this plugin on a weekend.

Therefore, it has neither the ambitions nor the functionality to compete with other mfa-services out there. Please keep that in mind when you deploy this.
 
## How will it work?
After you installed the plugin, a bunch of new objects are imported into IdentityIQ.
There are two new Capabilities
 - TinyMFA Activated Identity
 - View TinyMFA Plugin Activated Identity
 
Having one of the both capabilities assigned, a new icon will appear on your main menubar. From there, you have the option to have a look at "**Your QRCode**". You will find a QRCode that can be scanned with google-authenticator.
The "**TinyMFA Activated Identity**" is meant to be assigned to all identities that shall authenticate via google authenticator. Once assigned, the identity will be assigned a DynamicScope "**TinyMFA Authenticated**"

Last, you need to modify the login configuration of IdentityIQ. 

Go to **Global Settings** -> **Login Configuration** -> **MFA Configuration**. You will see a checkbox next to the label "**MFA TinyMFA**". Check it, then select the population "**TinyMFA Authenticated**" and add it to the list of "**MFA TinyMFA Populations**". 

Anyone belonging to that DynamicScope is now required to enter a totp token the next time they logon to the system.
