rule http11_10_rule {
 strings:
  $http = /HTTP\/1\.[01]/ nocase

 condition:
  any of them
}
