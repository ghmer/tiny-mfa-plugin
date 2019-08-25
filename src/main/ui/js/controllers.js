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
	
	/** AdminController Controller **/
    app.controller('AdminController', ['$scope', '$http', '$timeout', function($scope, $http, $timeout) {
        $scope.headline     = 'Tiny Multifactor Authentication - Admin Area';
        $scope.currentPage  = 1;
        $scope.numLimit     = 10;
        $scope.start        = 0;
        $scope.maxNumber    = 100;
        $scope.validations  = [];
        
        $scope.$watch('numLimit',function(newVal){
            if(newVal){
             $scope.pages=Math.ceil($scope.validations.length/$scope.numLimit);
            }
        });
        
        $scope.$watch('maxNumber',function(newVal){
            if(newVal){
             $scope.getValidationAttempts($scope.maxNumber);
             $scope.pages=Math.ceil($scope.validations.length/$scope.numLimit);
            }
        });
        
        $scope.$watch('validations',function(newVal){
            if(newVal){
             $scope.pages=Math.ceil($scope.validations.length/$scope.numLimit);
            }
        });
        
        $scope.hideNext=function(){
          if(($scope.start + $scope.numLimit) < $scope.validations.length){
            return false;
          }
          else 
          return true;
        };
        
        $scope.hidePrev=function(){
          if($scope.start===0){
            return true;
          }
          else 
          return false;
        };
        
        $scope.nextPage=function(){
          console.log("next pages");
          $scope.currentPage++;
          $scope.start=$scope.start+ $scope.numLimit;
          console.log( $scope.start)
        };
        
        $scope.PrevPage=function(){
          if($scope.currentPage>1){
            $scope.currentPage--;
          }
          console.log("next pages");
          $scope.start=$scope.start - $scope.numLimit;
          console.log( $scope.start)
        };
        
        $scope.getValidationAttempts = function() {
            $http({
                method  : "GET",
                withCredentials: true,
                xsrfHeaderName : "X-XSRF-TOKEN",
                xsrfCookieName : "CSRF-TOKEN",
                url : PluginHelper.getPluginRestUrl('tiny-mfa') + '/audit/' + $scope.maxNumber
            }).then(function mySuccess(response) {
                $scope.validations = response.data;

            }, function myError(response) {
                
            });
        };
        
        try {
            $scope.getValidationAttempts($scope.maxNumber);
        }catch(error) {
            
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