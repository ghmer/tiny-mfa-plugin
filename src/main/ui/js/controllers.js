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
		$scope.qrCodeError   = null;
		$scope.errorMessage  = null;
		$scope.qrCodeSuccess = null;
		
		function populateQrCode($scope, $http) {
			$http({
		        method  : "GET",
		        withCredentials: true,
		        xsrfHeaderName : "X-XSRF-TOKEN",
		        xsrfCookieName : "CSRF-TOKEN",
		        url : PluginHelper.getPluginRestUrl('tiny-mfa') + '/generateQrCodeData'
		    }).then(function mySuccess(response) {
		    	if(response.data.startsWith("<!DOCTYPE")) {
		    		// we probably hit a csrf issue
		    		$scope.errorMessage  = "There was an issue with generating the QRCode. Please proceed with cleaning your browsercookies and restarting the browser before trying again.";
			        $scope.qrCodeSuccess = null;
			        $scope.qrCodeError 	 = "Sorry, but the QRCode could not be created";
		    	} else {
		    		//generate qrcode 
		    		var qrCodeObject 	 = kjua({text: response.data});
			        $scope.qrCode 		 = qrCodeObject.src;
			        $scope.qrCodeError 	 = null;
			        $scope.qrCodeSuccess = "success";
		    	}
		    }, function myError(response) {
		    	$scope.errorMessage  = "There was an issue with generating the QRCode. Please proceed with cleaning your browsercookies and restarting the browser before trying again.";
			    $scope.qrCodeSuccess = null;
		        $scope.qrCodeError   = "Sorry, but the QRCode could not be created";
		    });
		};
		try {
			populateQrCode($scope, $http);
		}catch(error) {
			$scope.errorMessage  = error.message;
			$scope.qrCodeError   = "Sorry, but the QRCode could not be created";
	        $scope.qrCodeSuccess = null;
		}
		
	});
	
	/** ValidateController Controller **/
	app.controller('ValidateController', function($scope, $http) {
		$scope.headline = 'Validate Your QRCode';
		$scope.validationError 	 = null;
		$scope.validationSuccess = null;
		
		try {
			$scope.validateToken = function(tokenValue){
				$http({
			        method  : "GET",
			        withCredentials: true,
			        xsrfHeaderName : "X-XSRF-TOKEN",
			        xsrfCookieName : "CSRF-TOKEN",
			        url : PluginHelper.getPluginRestUrl('tiny-mfa') + '/validateToken/' + PluginHelper.getCurrentUsername() + '/' + tokenValue
			    }).then(function mySuccess(response) {
			    	if(response.data == "true") {
			    		$scope.validationSuccess = "Token validation successful";
				    	$scope.validationError   = null;
			    	} else {
			    		$scope.validationError   = "Token validation failed - " + response.data;
				    	$scope.validationSuccess = null;
			    	}
			    	
			    }, function myError(response) {
			    	$scope.validationError   = "Token validation failed - " + response.data;
			    	$scope.validationSuccess = null;
			    });
			};
		}catch(error) {
			$scope.validationError = error.message;
		}
	});
}());