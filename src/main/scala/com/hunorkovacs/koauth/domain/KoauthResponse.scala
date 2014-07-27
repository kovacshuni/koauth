package com.hunorkovacs.koauth.domain

trait KoauthResponse

case class ResponseOk(body: String) extends KoauthResponse

trait ResponseNok extends KoauthResponse

case class ResponseUnauthorized(body: String) extends ResponseNok

case class ResponseBadRequest(body: String) extends ResponseNok
