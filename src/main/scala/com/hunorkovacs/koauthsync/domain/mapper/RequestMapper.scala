package com.hunorkovacs.koauthsync.domain.mapper

import com.hunorkovacs.koauth.domain.KoauthRequest

trait RequestMapper[RequestType] {

  def map(source: RequestType): KoauthRequest
}
