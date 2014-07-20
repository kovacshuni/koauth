package com.hunorkovacs.koauth.domain.mapper

import com.hunorkovacs.koauth.domain.EnhancedRequest
import scala.concurrent.{ExecutionContext, Future}

trait OauthRequestMapper[RequestType] {

  def map(source: RequestType)(implicit ec: ExecutionContext): Future[EnhancedRequest]
}
