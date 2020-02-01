package com.hunorkovacs.koauth.service.consumer

import com.hunorkovacs.koauth.domain.KoauthRequest

trait ConsumerService {

  def createRequestTokenRequest(request: KoauthRequest, consumerKey: String, consumerSecret: String, callback: String): RequestWithInfo

  def createAccessTokenRequest(
      request: KoauthRequest,
      consumerKey: String,
      consumerSecret: String,
      requestToken: String,
      requestTokenSecret: String,
      verifier: String
  ): RequestWithInfo

  def createOauthenticatedRequest(
      request: KoauthRequest,
      consumerKey: String,
      consumerSecret: String,
      requestToken: String,
      requestTokenSecret: String
  ): RequestWithInfo

  def createGeneralSignedRequest(request: KoauthRequest): RequestWithInfo
}
