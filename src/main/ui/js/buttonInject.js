jQuery(document)
    .ready(
        function() {
          var tinyMfaPluginUrl = SailPoint.CONTEXT_PATH
              + '/plugins/pluginPage.jsf?pn=tiny_mfa_plugin';
          jQuery("ul.navbar-right li:first")
              .before(
                  '<li class="dropdown"><a href="'+ tinyMfaPluginUrl+ '" tabindex="0" role="menuitem" title="Multifactor Authentication">'
                      + '<i role="presenation" class="fa fa-mobile fa-lg example"></i>'
                      + '</a></li>');
        });