package com.hunorkovacs.koauth.service.consumer

import com.hunorkovacs.koauth.domain.KoauthRequest
import com.hunorkovacs.koauth.domain.OauthParams._
import com.hunorkovacs.koauth.service.Arithmetics.{concatItemsForSignature, createAuthorizationHeader, sign}
import com.hunorkovacs.koauth.service.DefaultTokenGenerator.generateNonce

case class RequestWithInfo(request: KoauthRequest, signatureBase: String, header: String)

trait ConsumerService {

  def createRequestTokenRequest(request: KoauthRequest,
                                consumerKey: String,
                                consumerSecret: String,
                                callback: String): RequestWithInfo

  def createAccessTokenRequest(request: KoauthRequest,
                               consumerKey: String,
                               consumerSecret: String,
                               requestToken: String,
                               requestTokenSecret: String,
                               verifier: String): RequestWithInfo

  def createOauthenticatedRequest(request: KoauthRequest,
                                  consumerKey: String,
                                  consumerSecret: String,
                                  requestToken: String,
                                  requestTokenSecret: String): RequestWithInfo

  def createGeneralSignedRequest(request: KoauthRequest): RequestWithInfo
}

object DefaultConsumerService extends ConsumerService {

  private val secretNames = Set(ConsumerSecretName, TokenSecretName)

  def createRequestTokenRequest(request: KoauthRequest,
                                consumerKey: String,
                                consumerSecret: String,
                                callback: String): RequestWithInfo = {
    createGeneralSignedRequest(
      KoauthRequest(request, ConsumerKeyName -> consumerKey
        :: ConsumerSecretName -> consumerSecret
        :: CallbackName -> callback
        :: basicParamList())
    )
  }

  def createAccessTokenRequest(request: KoauthRequest,
                               consumerKey: String,
                               consumerSecret: String,
                               requestToken: String,
                               requestTokenSecret: String,
                               verifier: String): RequestWithInfo = {
    createGeneralSignedRequest(
      KoauthRequest(request, ConsumerKeyName -> consumerKey
        :: ConsumerSecretName -> consumerSecret
        :: TokenName -> requestToken
        :: TokenSecretName -> requestTokenSecret
        :: VerifierName -> verifier
        :: basicParamList()
      )
    )
  }

  def createOauthenticatedRequest(request: KoauthRequest,
                                  consumerKey: String,
                                  consumerSecret: String,
                                  requestToken: String,
                                  requestTokenSecret: String): RequestWithInfo = {
    createGeneralSignedRequest(
      KoauthRequest(request, ConsumerKeyName -> consumerKey
        :: ConsumerSecretName -> consumerSecret
        :: TokenName -> requestToken
        :: TokenSecretName -> requestTokenSecret
        :: basicParamList())
    )
  }

  def createGeneralSignedRequest(request: KoauthRequest): RequestWithInfo = {
    val consumerSecret = request.oauthParamsMap.applyOrElse(ConsumerSecretName, (s: String) => "")
    val tokenSecret = request.oauthParamsMap.applyOrElse(TokenSecretName, (s: String) => "")
    val base = createSignatureBase(request)
    val header = createAuthorizationHeader(SignatureName -> sign(base, consumerSecret, tokenSecret)
      :: request.oauthParamsList.filterNot(p => secretNames(p._1)))
    RequestWithInfo(request, base, header)
  }

  def createSignatureBase(request: KoauthRequest): String = concatItemsForSignature(KoauthRequest(
    request.method,
    request.urlWithoutParams,
    request.urlParams,
    request.bodyParams,
    request.oauthParamsList.filterNot(p => secretNames(p._1))))

  private def basicParamList() = List(
    NonceName -> generateNonce,
    VersionName -> "1.0",
    SignatureMethodName -> "HMAC-SHA1",
    TimestampName -> (System.currentTimeMillis() / 1000).toString
  )
}
