package com.hunorkovacs.koauth.service.consumer

import java.util.{Calendar, TimeZone}

import com.hunorkovacs.koauth.domain.OauthParams._
import com.hunorkovacs.koauth.domain.KoauthRequest
import com.hunorkovacs.koauth.service.Arithmetics.{sign, concatItemsForSignature, createAuthorizationHeader}
import com.hunorkovacs.koauth.service.Generator.generateNonce

import scala.concurrent.{ExecutionContext, Future}

trait ConsumerService {

  def createRequestTokenRequest(request: KoauthRequest,
                                consumerKey: String,
                                consumerSecret: String,
                                callback: String)
                               (implicit ec: ExecutionContext): Future[RequestWithInfo]

  def createAuthorizeRequest(request: KoauthRequest,
                             consumerKey: String,
                             requestToken: String,
                             username: String,
                             password: String)
                            (implicit ec: ExecutionContext): Future[RequestWithInfo]

  def createAccessTokenRequest(request: KoauthRequest,
                               consumerKey: String,
                               consumerSecret: String,
                               requestToken: String,
                               requestTokenSecret: String,
                               verifier: String)
                              (implicit ec: ExecutionContext): Future[RequestWithInfo]

  def createOauthenticatedRequest(request: KoauthRequest,
                                  consumerKey: String,
                                  consumerSecret: String,
                                  requestToken: String,
                                  requestTokenSecret: String)
                                 (implicit ec: ExecutionContext): Future[RequestWithInfo]

  def createGeneralSignedRequest(request: KoauthRequest)
                                (implicit ec: ExecutionContext): Future[RequestWithInfo]
}

case class RequestWithInfo(request: KoauthRequest, signatureBase: String, header: String)

object DefaultConsumerService extends ConsumerService {

  override def createRequestTokenRequest(request: KoauthRequest,
                                         consumerKey: String,
                                         consumerSecret: String,
                                         callback: String)
                                        (implicit ec: ExecutionContext): Future[RequestWithInfo] = {
    Future {
      val paramsList = createBasicParamList().::((consumerKeyName, consumerKey))
        .::((consumerSecretName, consumerSecret))
        .::((callbackName, callback))
      KoauthRequest(request, paramsList)
    }.flatMap(createGeneralSignedRequest)
  }

  override def createAuthorizeRequest(request: KoauthRequest,
                                      consumerKey: String,
                                      requestToken: String,
                                      username: String,
                                      password: String)
                                     (implicit ec: ExecutionContext): Future[RequestWithInfo] = {
    Future {
      val paramsList = createBasicParamList().::((consumerKeyName, consumerKey))
        .::((tokenName, requestToken))
        .::((usernameName, username))
        .::((passwordName, password))
      val header = createAuthorizationHeader(paramsList)
      val complementedRequest = KoauthRequest(request, paramsList)
      RequestWithInfo(complementedRequest, "", header)
    }
  }

  override def createAccessTokenRequest(request: KoauthRequest,
                                        consumerKey: String,
                                        consumerSecret: String,
                                        requestToken: String,
                                        requestTokenSecret: String,
                                        verifier: String)
                                       (implicit ec: ExecutionContext): Future[RequestWithInfo] = {
    Future {
      val paramsList = createBasicParamList().::((consumerKeyName, consumerKey))
      .::((consumerSecretName, consumerSecret))
      .::((tokenName, requestToken))
      .::((tokenSecretName, requestTokenSecret))
      .::((verifierName, verifier))
      KoauthRequest(request, paramsList)
    }.flatMap(createGeneralSignedRequest)
  }

  override def createOauthenticatedRequest(request: KoauthRequest,
                                           consumerKey: String,
                                           consumerSecret: String,
                                           requestToken: String,
                                           requestTokenSecret: String)
                                          (implicit ec: ExecutionContext): Future[RequestWithInfo] = {
    Future {
      val paramsList = createBasicParamList().::((consumerKeyName, consumerKey))
        .::((consumerSecretName, consumerSecret))
        .::((tokenName, requestToken))
        .::((tokenSecretName, requestTokenSecret))
      KoauthRequest(request, paramsList)
    }.flatMap(createGeneralSignedRequest)
  }

  private def createBasicParamList(): List[(String, String)] = {
    List((nonceName, generateNonce),
      (versionName, "1.0"),
      (signatureMethodName, "HMAC-SHA1"),
      (timestampName, (System.currentTimeMillis / 1000).toString))
  }

  def createGeneralSignedRequest(request: KoauthRequest)
                                (implicit ec: ExecutionContext): Future[RequestWithInfo] = {
    Future {
      val consumerSecret = request.oauthParamsMap.applyOrElse(consumerSecretName, (s: String) => "")
      val tokenSecret = request.oauthParamsMap.applyOrElse(tokenSecretName, (s: String) => "")
      val base = createSignatureBase(request)
      val signature = sign(base, consumerSecret, tokenSecret)
      val list = request.oauthParamsList
        .filterNot(param => consumerSecretName == param._1 || tokenSecretName == param._1)
        .::((signatureName, signature))
      val header = createAuthorizationHeader(list)
      RequestWithInfo(request, base, header)
    }
  }

  def createSignatureBase(request: KoauthRequest): String = {
    val filteredList = request.oauthParamsList
      .filterNot(param => consumerSecretName == param._1 || tokenSecretName == param._1)
    concatItemsForSignature(new KoauthRequest(request.method,
      request.urlWithoutParams,
      request.urlParams,
      request.bodyParams,
      filteredList))
  }
}
