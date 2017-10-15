var url = SailPoint.CONTEXT_PATH + '/plugins/pluginPage.jsf?pn=tiny-mfa-plugin';
jQuery(document).ready(function(){
    jQuery("ul.navbar-right li:first")
        .before(
            '<li class="dropdown">' +
            '		<a href="' + url + '" tabindex="0" role="menuitem" title="Multifactor Authentication">' +
            '			<i role="presenation" class="fa fa-key fa-lg example"></i>' +
            '		</a>' +
            '</li>'
        );
});