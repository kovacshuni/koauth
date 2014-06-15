package com.hunorkovacs.koauth.domain.exception

case class OauthBadRequestException(message: String) extends RuntimeException(message)
//      HTTP 400 Bad Request
//      Unsupported parameter
//      Unsupported signature method
//      Missing required parameter
//      Duplicated OAuth Protocol Parameter
