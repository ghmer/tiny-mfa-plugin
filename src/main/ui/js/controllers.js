(function () {
	'use strict';
  
	var app = angular.module('tinyMfaPluginApp');
	
	/** HOME Controller **/
	app.controller('NavigateController', ['$scope', '$http', '$timeout', function($scope, $http, $timeout) {
	    $scope.admin   = false;
        $scope.isAdmin = function() {
            $http({
                method  : "GET",
                withCredentials: true,
                xsrfHeaderName : "X-XSRF-TOKEN",
                xsrfCookieName : "CSRF-TOKEN",
                url : PluginHelper.getPluginRestUrl('tiny-mfa') + '/accounts/isAdmin'
            }).then(function mySuccess(response) {
                $scope.admin = response.data;
                
            }, function myError(response) {
                $scope.admin = false;
            });
        };
        
        try {
            $scope.isAdmin();
        }catch(error) {
            alert(error);
        }
       
    }]);
	
	app.controller('HomeController', ['$scope', '$http', '$timeout', function($scope, $http, $timeout) {
        $scope.headline            = 'Welcome!';
        $scope.iosAppstoreLink     = '';
        $scope.androidAppstoreLink = '';
        
        function populateAppstoreLinks($scope, $http) {
            $http({
                method  : "GET",
                withCredentials: true,
                xsrfHeaderName : "X-XSRF-TOKEN",
                xsrfCookieName : "CSRF-TOKEN",
                url : PluginHelper.getPluginRestUrl('tiny-mfa') + '/getAppstoreLinks'
            }).then(function mySuccess(response) {
                var appstoreLinkObject     = response.data;
                $scope.iosAppstoreLink     = appstoreLinkObject.iosAppstoreLink;
                $scope.androidAppstoreLink = appstoreLinkObject.androidAppstoreLink;
            
            }, function myError(response) {
                $scope.errorMessage  = "There was an issue retrieving the appstore links to the MFA apps.";
                
                $timeout(function() {
                    $scope.errorMessage  = null;
                }, 3000);
            });
        };
        try {
            populateAppstoreLinks($scope, $http);
        }catch(error) {
            $scope.errorMessage  = error.message;
        }
        
    }]);
	
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
		        url : PluginHelper.getPluginRestUrl('tiny-mfa') + '/token/qrcode'
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
		$scope.headline = 'Validate Your Setup';
		$scope.validationError 	 = null;
		$scope.validationSuccess = null;
		
		try {
			$scope.validateToken = function(tokenValue){
				$http({
			        method  : "GET",
			        withCredentials: true,
			        xsrfHeaderName : "X-XSRF-TOKEN",
			        xsrfCookieName : "CSRF-TOKEN",
			        url : PluginHelper.getPluginRestUrl('tiny-mfa') + '/token/validate/' + PluginHelper.getCurrentUsername() + '/' + tokenValue
			    }).then(function mySuccess(response) {
			    	if(response.data == "true") {
			    		$scope.validationSuccess = "Token validation successful";
				    	$scope.validationError   = null;
				    	$timeout(function() {
				    		$scope.validationSuccess = null;
			            }, 3000);
			    	} else {
			    		$scope.validationError   = "Token validation failed";
				    	$scope.validationSuccess = null;
				    	$timeout(function() {
				    		$scope.validationError 	 = null;
			            }, 3000);
			    	}
			    	
			    }, function myError(response) {
			    	$scope.validationError   = "Token validation failed";
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
	
	/** ActivateController Controller **/
    app.controller('ActivateController', ['$scope', '$http', '$timeout', function($scope, $http, $timeout) {
        $scope.headline = 'Activate Multifactor Authentication';
        $scope.activationError   = null;
        $scope.activationSuccess = null;
        
        try {
            $scope.activateToken = function(tokenValue){
                $http({
                    method  : "GET",
                    withCredentials: true,
                    xsrfHeaderName : "X-XSRF-TOKEN",
                    xsrfCookieName : "CSRF-TOKEN",
                    url : PluginHelper.getPluginRestUrl('tiny-mfa') + '/token/activate/' + PluginHelper.getCurrentUsername() + '/' + tokenValue
                }).then(function mySuccess(response) {
                    if(response.data == "true") {
                        $scope.activationSuccess = "Token activation successful";
                        $scope.activationError   = null;
                        $timeout(function() {
                            $scope.activationSuccess = null;
                        }, 3000);
                    } else {
                        $scope.activationError   = "Token activation failed";
                        $scope.activationSuccess = null;
                        $timeout(function() {
                            $scope.activationError   = null;
                        }, 3000);
                    }
                    
                }, function myError(response) {
                    $scope.activationError   = "Token activation failed";
                    $scope.activationSuccess = null;
                    $timeout(function() {
                        $scope.activationError   = null;
                    }, 3000);
                });
            };
        }catch(error) {
            $scope.activationError = error.message;
            $timeout(function() {
                $scope.activationError   = null;
            }, 3000);
        }
    }]);
}());