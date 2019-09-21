(function() {
  'use strict';

  var app = angular.module('tinyMfaPluginApp');

  app.directive('tinyMfaNavigation', function() {
    return {
      controller : 'NavigateController',
      controllerAs : 'controller',
      restrict : 'E',
      scope : {
        activelink : '@'
      },
      templateUrl : PluginHelper.getPluginFileUrl('tiny_mfa_plugin',
      'ui/partials/directives/navigationDirective.html')
    };
  });

  app.directive('tinyMfaQuickstart', function() {
    return {
      controller : 'HomeController',
      controllerAs : 'controller',
      restrict : 'E',
      replace : true,
      templateUrl : PluginHelper.getPluginFileUrl('tiny_mfa_plugin',
      'ui/partials/directives/quickstartDirective.html')
    };
  });

  app.directive('tinyMfaValidator', function() {
    return {
      controller : 'ValidateController',
      controllerAs : 'controller',
      restrict : 'E',
      replace : true,
      templateUrl : PluginHelper.getPluginFileUrl('tiny_mfa_plugin',
      'ui/partials/directives/validatorDirective.html')
    };
  });

  app.directive('tinyMfaActivator', function() {
    return {
      controller : 'ActivateController',
      controllerAs : 'controller',
      restrict : 'E',
      replace : true,
      templateUrl : PluginHelper.getPluginFileUrl('tiny_mfa_plugin',
      'ui/partials/directives/activatorDirective.html')
    };
  });

  app.directive('tinyMfaQrcode', function() {
    return {
      controller : 'QRCodeController',
      controllerAs : 'controller',
      restrict : 'E',
      replace : true,
      templateUrl : PluginHelper.getPluginFileUrl('tiny_mfa_plugin',
      'ui/partials/directives/qrcodeDirective.html')
    };
  });

  app.directive('tinyMfaAuditTable', function() {
    return {
      controller : 'AdminController',
      controllerAs : 'controller',
      restrict : 'E',
      replace : true,
      templateUrl : PluginHelper.getPluginFileUrl('tiny_mfa_plugin',
      'ui/partials/directives/auditTableDirective.html')
    };
  });
  
  app.directive('tinyMfaManageUser', function() {
    return {
      controller : 'AdminController',
      controllerAs : 'controller',
      restrict : 'E',
      replace : true,
      templateUrl : PluginHelper.getPluginFileUrl('tiny_mfa_plugin',
      'ui/partials/directives/manageUserDirective.html')
    };
  });
  
  app.directive('tinyMfaEnrollUser', function() {
    return {
      controller : 'AdminController',
      controllerAs : 'controller',
      restrict : 'E',
      replace : true,
      templateUrl : PluginHelper.getPluginFileUrl('tiny_mfa_plugin',
      'ui/partials/directives/enrollUserDirective.html')
    };
  });

}());
