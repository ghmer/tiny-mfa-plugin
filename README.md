# tiny-mfa-plugin
After some time of hacking, here is the tiny-multifactor-authentication plugin for IdentityIQ!
It will provide you with a (very, very) basic interface for enrolling MFA with IdentityIQ.

## Why is there a need for such a plugin?
There is absolutely no need for this plugin! This was created as part of the new MFA capabilities of SailPoint IdentityIQ 7.2. As I didn't own a multifactor-authentication server and also was kinda interested in how this stuff works, I decided to build this plugin on a weekend.

Therefore, it has neither the ambitions nor the functionality to compete with other mfa-services out there. Please keep that in mind when you deploy this.
 
## How will it work?
After you installed the plugin, a new icon will appear on your main menubar. From there, you have the option to have a look at "Your QRCode". You will find a QRCode that can be scanned with google-authenticator.
