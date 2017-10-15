(function () {
	'use strict';
  
	var app = angular.module('tinyMfaPluginApp');
	
	/** HOME Controller **/
	app.controller('HomeController', function($scope) {
		$scope.headline = 'Welcome!';
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
	
	/** ValidateController Controller **/
	app.controller('ValidateController', function($scope, $http) {
		$scope.headline = 'Validate Your QRCode';
		
		$scope.validateToken = function(tokenValue){
			$http({
		        method : "GET",
		        url : PluginHelper.getPluginRestUrl('tiny-mfa') + '/validateToken/' + PluginHelper.getCurrentUsername() + '/' + tokenValue
		    }).then(function mySuccess(response) {
		    	if(response.data == "true") {
		    		$scope.validationSuccess = "Token validation successful";
			    	$scope.validationError = null;
		    	} else {
		    		$scope.validationError = "Token validation failed - " + response.data;
			    	$scope.validationSuccess = null;
		    	}
		    	
		    }, function myError(response) {
		    	$scope.validationError = "Token validation failed - " + response.data;
		    	$scope.validationSuccess = null;
		    });
		};
	});
}());