package com.hunorkovacs.koauth.service.consumer

import com.hunorkovacs.koauth.domain.KoauthRequest

case class RequestWithInfo(
    request: KoauthRequest,
    signatureBase: String,
    header: String)
