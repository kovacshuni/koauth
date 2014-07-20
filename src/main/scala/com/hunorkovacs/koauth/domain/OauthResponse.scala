package com.hunorkovacs.koauth.domain

trait OauthResponse

case class ResponseOk(body: String) extends OauthResponse

case class ResponseUnauthorized(body: String) extends OauthResponse

case class ResponseBadRequest(body: String) extends OauthResponse
