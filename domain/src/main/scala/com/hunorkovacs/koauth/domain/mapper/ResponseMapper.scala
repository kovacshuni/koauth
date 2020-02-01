package com.hunorkovacs.koauth.domain.mapper

import com.hunorkovacs.koauth.domain.KoauthResponse

import scala.concurrent.Future

trait ResponseMapper[ResponseType] {

  def map(source: KoauthResponse): Future[ResponseType]
}
