package com.hunorkovacs.koauth.domain

trait Response

case class ResponseOk(body: String) extends Response

trait ResponseNok extends Response

case class ResponseUnauthorized(body: String) extends ResponseNok

case class ResponseBadRequest(body: String) extends ResponseNok
