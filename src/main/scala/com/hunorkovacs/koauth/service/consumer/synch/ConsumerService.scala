package com.hunorkovacs.koauth.service.consumer.synch

import com.hunorkovacs.koauth.domain.OauthParams._
import com.hunorkovacs.koauth.domain.KoauthRequest
import com.hunorkovacs.koauth.service.Arithmetics.{concatItemsForSignature, createAuthorizationHeader, sign}
import com.hunorkovacs.koauth.service.DefaultTokenGenerator.generateNonce
import com.hunorkovacs.koauth.service.consumer.RequestWithInfo


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

object ConsumerService extends ConsumerService {

  val secretNames = Set(ConsumerSecretName, TokenSecretName)

  val basicParamList = List(
    NonceName -> generateNonce,//TODO: should we assign a nonce to a val or should it get a new value every time and be a def?
    VersionName -> "1.0",
    SignatureMethodName -> "HMAC-SHA1"
  )

  def createRequestTokenRequest(request: KoauthRequest,
    consumerKey: String,
    consumerSecret: String,
    callback: String): RequestWithInfo = {

    createGeneralSignedRequest(
      KoauthRequest(request, ConsumerKeyName -> consumerKey
        :: ConsumerSecretName -> consumerSecret
        :: CallbackName -> callback
        :: createBasicParamList())
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
        :: createBasicParamList()
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
        :: createBasicParamList())
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

  def createBasicParamList(currentTimeMillis: Long = System.currentTimeMillis): List[(String, String)] =
    TimestampName -> (currentTimeMillis / 1000).toString :: basicParamList
}



