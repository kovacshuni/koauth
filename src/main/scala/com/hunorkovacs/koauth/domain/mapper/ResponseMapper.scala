package com.hunorkovacs.koauth.domain.mapper

import scala.concurrent.{ExecutionContext, Future}
import com.hunorkovacs.koauth.domain.OauthResponseOk

trait ResponseMapper[ResponseType] {

  def map(source: Future[OauthResponseOk])(implicit ec: ExecutionContext): Future[ResponseType]
}
