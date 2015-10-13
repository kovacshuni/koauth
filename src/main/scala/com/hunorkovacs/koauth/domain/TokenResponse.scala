package com.hunorkovacs.koauth.domain

case class TokenResponse(token: String, secret: String, userId: Option[String], screenName: Option[String])
