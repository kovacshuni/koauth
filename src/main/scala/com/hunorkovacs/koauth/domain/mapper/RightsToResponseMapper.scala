package com.hunorkovacs.koauth.domain.mapper

import com.hunorkovacs.koauth.domain.Rights
import scala.concurrent.{ExecutionContext, Future}

trait RightsToResponseMapper[ResponseType] {

  def map(rightsF: Future[Rights])(implicit ec: ExecutionContext): Future[ResponseType]
}
