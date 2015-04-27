package com.hunorkovacs.koauthsync.domain.mapper

import scala.concurrent.Future
import com.hunorkovacs.koauthsync.domain.KoauthResponse

trait ResponseMapper[ResponseType] {

  def map(source: KoauthResponse): Future[ResponseType]
}
