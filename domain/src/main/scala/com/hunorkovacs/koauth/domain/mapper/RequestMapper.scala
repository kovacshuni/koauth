package com.hunorkovacs.koauth.domain.mapper

import com.hunorkovacs.koauth.domain.KoauthRequest

import scala.concurrent.Future

trait RequestMapper[RequestType] {

  def map(source: RequestType): Future[KoauthRequest]
}
