package com.hunorkovacs.koauth.domain.mapper

import scala.concurrent.{ExecutionContext, Future}
import com.hunorkovacs.koauth.domain.KoauthResponse

trait ResponseMapper[ResponseType] {

  def map(source: KoauthResponse)(implicit ec: ExecutionContext): Future[ResponseType]
}
