package com.hunorkovacs.koauthsync.domain.mapper

import com.hunorkovacs.koauthsync.domain.KoauthResponse

trait ResponseMapper[ResponseType] {

  def map(source: KoauthResponse): ResponseType
}
