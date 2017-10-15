(function () {
	'use strict';
  
	var app = angular.module('tinyMfaPluginApp');
	
	/** HOME Controller **/
	app.controller('HomeController', function($scope) {
		$scope.headline = 'General Information';
	});
	
	/** QRCode Controller **/
	app.controller('QRCodeController', function($scope, $http) {
		$scope.headline = 'Your QRCode';
		
		function populateQrCode($scope, $http) {
			$http({
		        method : "GET",
		        url : PluginHelper.getPluginRestUrl('tiny-mfa') + '/generateQrCodeData'
		    }).then(function mySuccess(response) {
		    	var el = kjua({text: response.data});
		        $scope.qrCode = el.src;
		        $scope.errorMessage = "";
		    }, function myError(response) {
		        $scope.errorMessage = response.statusText;
		    });
		};
		
		populateQrCode($scope, $http);
	});
}());