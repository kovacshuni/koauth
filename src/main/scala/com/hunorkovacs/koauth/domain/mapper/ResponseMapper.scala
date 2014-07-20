package com.hunorkovacs.koauth.domain.mapper

import scala.concurrent.{ExecutionContext, Future}
import com.hunorkovacs.koauth.domain.ResponseOk

trait ResponseMapper[ResponseType] {

  def map(source: Future[ResponseOk])(implicit ec: ExecutionContext): Future[ResponseType]
}
