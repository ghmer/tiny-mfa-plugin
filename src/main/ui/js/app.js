(function () {
	'use strict';
	
	var app = angular.module('tinyMfaPluginApp', ['ngRoute']);
	app.config(function($routeProvider) {
		$routeProvider

		.when('/', {
			templateUrl : PluginHelper.getPluginFileUrl('tiny-mfa-plugin', 'ui/partials/home.html'),
			controller  : 'HomeController'
		})

		.when('/home', {
			templateUrl : PluginHelper.getPluginFileUrl('tiny-mfa-plugin', 'ui/partials/home.html'),
			controller  : 'HomeController'
		})
		
		.when('/qrcode', {
			templateUrl : PluginHelper.getPluginFileUrl('tiny-mfa-plugin', 'ui/partials/qrcode.html'),
			controller  : 'QRCodeontroller'
		})

		.otherwise({redirectTo: '/'});
	});
}());