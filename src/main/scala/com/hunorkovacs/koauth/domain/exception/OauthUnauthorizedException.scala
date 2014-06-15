package com.hunorkovacs.koauth.domain.exception

case class OauthUnauthorizedException(message: String) extends RuntimeException(message)
//      Invalid Consumer Key
//      Invalid / expired Token
//      Invalid signature
//      Invalid / used nonce
