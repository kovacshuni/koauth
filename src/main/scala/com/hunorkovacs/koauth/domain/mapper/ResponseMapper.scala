package com.hunorkovacs.koauth.domain.mapper

import scala.concurrent.Future
import com.hunorkovacs.koauth.domain.KoauthResponse

trait ResponseMapper[ResponseType] {

  def map(source: KoauthResponse): Future[ResponseType]
}
