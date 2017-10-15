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
		
		function populateTable($scope, $http) {
			$http({
		        method : "GET",
		        url : PluginHelper.getPluginRestUrl('password-pronunciation') + '/data'
		    }).then(function mySuccess(response) {
		        $scope.data1 = response.data;
		    }, function myError(response) {
		        $scope.data1 = response.statusText;
		    });
		};
	});
}());