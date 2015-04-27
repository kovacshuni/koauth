package com.hunorkovacs.koauthsync.domain.mapper

import com.hunorkovacs.koauthsync.domain.KoauthRequest

trait RequestMapper[RequestType] {

  def map(source: RequestType): KoauthRequest
}
