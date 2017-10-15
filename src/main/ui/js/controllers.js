(function () {
	'use strict';
  
	var app = angular.module('tinyMfaPluginApp');
	
	/** HOME Controller **/
	app.controller('HomeController', function($scope) {
		$scope.headline = 'General Information';
	});
	
	/** QRCode Controller **/
	app.controller('QRCodeController', function($scope) {
		$scope.headline = 'Your QRCode';
		
		function populateQrCode($scope, $http) {
			$http({
		        method : "GET",
		        url : PluginHelper.getPluginRestUrl('tiny-mfa') + '/demoQrCodeData'
		    }).then(function mySuccess(response) {
		        $scope.qrCode = response.data;
		    }, function myError(response) {
		        $scope.qrCode = response.statusText;
		    });
		};
		
		populateQrCode($scope, $http);
	});
}());