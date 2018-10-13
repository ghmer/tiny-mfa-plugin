(function () {
	'use strict';
	
	var app = angular.module('tinyMfaPluginApp', ['ngRoute']);
	app.config(function($routeProvider) {
		$routeProvider

		.when('/', {
			templateUrl : PluginHelper.getPluginFileUrl('tiny_mfa_plugin', 'ui/partials/home.html'),
			controller  : 'HomeController'
		})

		.when('/home', {
			templateUrl : PluginHelper.getPluginFileUrl('tiny_mfa_plugin', 'ui/partials/home.html'),
			controller  : 'HomeController'
		})
		
		.when('/qrcode', {
			templateUrl : PluginHelper.getPluginFileUrl('tiny_mfa_plugin', 'ui/partials/qrcode.html'),
			controller  : 'QRCodeController'
		})
		
		.when('/validate', {
            templateUrl : PluginHelper.getPluginFileUrl('tiny_mfa_plugin', 'ui/partials/validate.html'),
            controller  : 'ValidateController'
        })
        
        .when('/activate', {
            templateUrl : PluginHelper.getPluginFileUrl('tiny_mfa_plugin', 'ui/partials/activate.html'),
            controller  : 'ActivateController'
        })

		.otherwise({redirectTo: '/'});
	});
	
	//this fixes the escaped slashes
	app.config(['$locationProvider', function($locationProvider) {
		  $locationProvider.hashPrefix('');
	}]);
}());