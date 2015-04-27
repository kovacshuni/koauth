package com.hunorkovacs.koauthsync.domain.mapper

import com.hunorkovacs.koauthsync.domain.KoauthRequest
import scala.concurrent.{ExecutionContext, Future}

trait RequestMapper[RequestType] {

  def map(source: RequestType): Future[KoauthRequest]
}
