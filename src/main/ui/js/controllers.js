(function () {
	'use strict';
  
	var app = angular.module('tinyMfaPluginApp');
	
	/** HOME Controller **/
	app.controller('HomeController', function($scope) {
		$scope.headline = 'Welcome!';
	});
	
	/** QRCode Controller **/
	app.controller('QRCodeController', ['$scope', '$http', '$timeout', function($scope, $http, $timeout) {
		$scope.headline = 'Your QRCode';
		$scope.qrCodeError   = null;
		$scope.errorMessage  = null;
		
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
			        $scope.qrCodeError 	 = "Sorry, but the QRCode could not be created";
			        $timeout(function() {
			        	$scope.qrCodeError   = null;
			    		$scope.errorMessage  = null;
		            }, 3000);
		    	} else {
		    		//generate qrcode 
		    		var qrCodeObject 	 = kjua({text: response.data});
			        $scope.qrCode 		 = qrCodeObject.src;
			        $scope.qrCodeError 	 = null;
		    	}
		    }, function myError(response) {
		    	$scope.errorMessage  = "There was an issue with generating the QRCode. Please proceed with cleaning your browsercookies and restarting the browser before trying again.";
		        $scope.qrCodeError   = "Sorry, but the QRCode could not be created";
		        
		        $timeout(function() {
		        	$scope.qrCodeError   = null;
		    		$scope.errorMessage  = null;
	            }, 3000);
		    });
		};
		try {
			populateQrCode($scope, $http);
		}catch(error) {
			$scope.errorMessage  = error.message;
			$scope.qrCodeError   = "Sorry, but the QRCode could not be created";
		}
		
	}]);
	
	/** ValidateController Controller **/
	app.controller('ValidateController', ['$scope', '$http', '$timeout', function($scope, $http, $timeout) {
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
				    	$timeout(function() {
				    		$scope.validationSuccess = null;
			            }, 3000);
			    	} else {
			    		$scope.validationError   = "Token validation failed - " + response.data;
				    	$scope.validationSuccess = null;
				    	$timeout(function() {
				    		$scope.validationError 	 = null;
			            }, 3000);
			    	}
			    	
			    }, function myError(response) {
			    	$scope.validationError   = "Token validation failed - " + response.data;
			    	$scope.validationSuccess = null;
			    	$timeout(function() {
			    		$scope.validationError 	 = null;
		            }, 3000);
			    });
			};
		}catch(error) {
			$scope.validationError = error.message;
			$timeout(function() {
	    		$scope.validationError 	 = null;
            }, 3000);
		}
	}]);
}());