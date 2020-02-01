package com.hunorkovacs.koauth.service.consumer

import com.hunorkovacs.koauth.domain.KoauthRequest
import com.hunorkovacs.koauth.domain.OauthParams._
import com.hunorkovacs.koauth.service.Arithmetics.{concatItemsForSignature, createAuthorizationHeader, sign}
import com.hunorkovacs.koauth.service.DefaultTokenGenerator.generateNonce

object DefaultConsumerService extends ConsumerService {
  private val secretNames = Set(ConsumerSecretName, TokenSecretName)

  override def createRequestTokenRequest(
      request: KoauthRequest,
      consumerKey: String,
      consumerSecret: String,
      callback: String
    ): RequestWithInfo = {
    createGeneralSignedRequest(
      KoauthRequest(
        request,
        ConsumerKeyName -> consumerKey
          :: ConsumerSecretName -> consumerSecret
          :: CallbackName -> callback
          :: basicParamList()
      )
    )
  }

  override def createAccessTokenRequest(
      request: KoauthRequest,
      consumerKey: String,
      consumerSecret: String,
      requestToken: String,
      requestTokenSecret: String,
      verifier: String
    ): RequestWithInfo = {
    createGeneralSignedRequest(
      KoauthRequest(
        request,
        ConsumerKeyName -> consumerKey
          :: ConsumerSecretName -> consumerSecret
          :: TokenName -> requestToken
          :: TokenSecretName -> requestTokenSecret
          :: VerifierName -> verifier
          :: basicParamList()
      )
    )
  }

  override def createOauthenticatedRequest(
      request: KoauthRequest,
      consumerKey: String,
      consumerSecret: String,
      requestToken: String,
      requestTokenSecret: String
    ): RequestWithInfo = {
    createGeneralSignedRequest(
      KoauthRequest(
        request,
        ConsumerKeyName -> consumerKey
          :: ConsumerSecretName -> consumerSecret
          :: TokenName -> requestToken
          :: TokenSecretName -> requestTokenSecret
          :: basicParamList()
      )
    )
  }

  override def createGeneralSignedRequest(request: KoauthRequest): RequestWithInfo = {
    val consumerSecret = request.oauthParamsMap.applyOrElse(ConsumerSecretName, (_: String) => "")
    val tokenSecret = request.oauthParamsMap.applyOrElse(TokenSecretName, (_: String) => "")
    val base = createSignatureBase(request)
    val header = createAuthorizationHeader(
      SignatureName -> sign(base, consumerSecret, tokenSecret)
        :: request.oauthParamsList.filterNot(p => secretNames(p._1))
    )
    RequestWithInfo(request, base, header)
  }

  def createSignatureBase(request: KoauthRequest): String =
    concatItemsForSignature(
      KoauthRequest(
        request.method,
        request.urlWithoutParams,
        request.urlParams,
        request.bodyParams,
        request.oauthParamsList.filterNot(p => secretNames(p._1))
      )
    )

  private def basicParamList() = List(
    NonceName -> generateNonce,
    VersionName -> "1.0",
    SignatureMethodName -> "HMAC-SHA1",
    TimestampName -> (System.currentTimeMillis() / 1000).toString
  )
}
