package com.hunorkovacs.koauthsync.domain.mapper

import com.hunorkovacs.koauth.domain.KoauthResponse

trait ResponseMapper[ResponseType] {

  def map(source: KoauthResponse): ResponseType
}
