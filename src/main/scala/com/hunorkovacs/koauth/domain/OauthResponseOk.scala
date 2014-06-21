package com.hunorkovacs.koauth.domain

trait OauthResponse

case class OauthResponseOk(body: String) extends OauthResponse

case class OauthResponseUnauthorized(body: String) extends OauthResponse

case class OauthResponseBadRequest(body: String) extends OauthResponse
