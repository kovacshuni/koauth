package com.hunorkovacs.koauth.service

import java.util.{TimeZone, Calendar}

import com.hunorkovacs.koauth.domain.OauthParams._
import com.hunorkovacs.koauth.domain.Request
import com.hunorkovacs.koauth.service.DefaultVerifier.sign
import com.hunorkovacs.koauth.service.Arithmetics.{createAuthorizationHeader, concatItemsForSignature}
import com.hunorkovacs.koauth.service.Generator.generateNonce

import scala.concurrent.{ExecutionContext, Future}

trait ConsumerService {

  def createRequestTokenRequest(request: Request,
                                consumerKey: String,
                                consumerSecret: String,
                                callback: String)
                               (implicit ec: ExecutionContext): Future[String]

  def createAuthorizeRequest(request: Request,
                             consumerKey: String,
                             requestToken: String,
                             username: String,
                             password: String)
                            (implicit ec: ExecutionContext): Future[String]

  def createAccessTokenRequest(request: Request,
                               consumerKey: String,
                               consumerSecret: String,
                               requestToken: String,
                               requestTokenSecret: String,
                               verifier: String)
                              (implicit ec: ExecutionContext): Future[String]

  def createOauthenticatedRequest(request: Request,
                                  consumerKey: String,
                                  consumerSecret: String,
                                  requestToken: String,
                                  requestTokenSecret: String)
                                 (implicit ec: ExecutionContext): Future[String]

  def createGeneralSignedRequest(request: Request)
                                (implicit ec: ExecutionContext): Future[String]
}

object DefaultConsumerService extends ConsumerService {

  private val CalendarGMT = Calendar.getInstance(TimeZone.getTimeZone("GMT"))

  override def createRequestTokenRequest(request: Request,
                                         consumerKey: String,
                                         consumerSecret: String,
                                         callback: String)
                                        (implicit ec: ExecutionContext): Future[String] = {
    val paramsList = createBasicParamList().::((consumerKeyName, consumerKey))
      .::((consumerSecretName, consumerSecret))
      .::((callbackName, callback))
    val enhanced = Request(request, paramsList)

    createGeneralSignedRequest(enhanced)
  }

  override def createAuthorizeRequest(request: Request,
                                      consumerKey: String,
                                      requestToken: String,
                                      username: String,
                                      password: String)
                                     (implicit ec: ExecutionContext): Future[String] = {
    Future {
      createBasicParamList().::((consumerKeyName, consumerKey))
        .::((tokenName, requestToken))
        .::((usernameName, username))
        .::((passwordName, password))
    }.flatMap(createAuthorizationHeader)
  }

  override def createAccessTokenRequest(request: Request,
                                        consumerKey: String,
                                        consumerSecret: String,
                                        requestToken: String,
                                        requestTokenSecret: String,
                                        verifier: String)
                                       (implicit ec: ExecutionContext): Future[String] = {
    val paramsList = createBasicParamList().::((consumerKeyName, consumerKey))
      .::((consumerSecretName, consumerSecret))
      .::((tokenName, requestToken))
      .::((tokenSecretName, requestTokenSecret))
      .::((verifierName, verifier))
    val enhanced = Request(request, paramsList)

    createGeneralSignedRequest(enhanced)
  }

  override def createOauthenticatedRequest(request: Request,
                                           consumerKey: String,
                                           consumerSecret: String,
                                           requestToken: String,
                                           requestTokenSecret: String)
                                          (implicit ec: ExecutionContext): Future[String] = {
    val paramsList = createBasicParamList().::((consumerKeyName, consumerKey))
      .::((consumerSecretName, consumerSecret))
      .::((tokenName, requestToken))
      .::((tokenSecretName, requestTokenSecret))
    val enhanced = Request(request, paramsList)

    createGeneralSignedRequest(enhanced)
  }

  private def createBasicParamList(): List[(String, String)] = {
    List((nonceName, generateNonce),
      (versionName, "1.0"),
      (signatureMethodName, "HMAC-SHA1"),
      (timestampName, CalendarGMT.getTimeInMillis.toString))
  }

  def createGeneralSignedRequest(request: Request)
                                (implicit ec: ExecutionContext): Future[String] = {
    signRequest(request) flatMap { signature =>
      Future(request.oauthParamsList
          .filterNot(param => consumerSecretName == param._1 || tokenSecretName == param._1)
          .::((signatureName, signature)))
        .flatMap(createAuthorizationHeader)
    }
  }

  def createSignatureBase(request: Request)
                         (implicit ec: ExecutionContext): Future[String] = {
    Future {
      val filteredList = request.oauthParamsList
        .filterNot(param => consumerSecretName == param._1 || tokenSecretName == param._1)
      new Request(request.method,
        request.urlWithoutParams,
        request.urlParams,
        request.bodyParams,
        filteredList,
        filteredList.toMap)
    }.flatMap(concatItemsForSignature)
  }

  def signRequest(request: Request)
                 (implicit ec: ExecutionContext): Future[String] = {
    for {
      base <- createSignatureBase(request)
      consumerSecret = request.oauthParamsMap(consumerSecretName)
      tokenSecret = request.oauthParamsMap.applyOrElse(tokenSecretName, (s: String) => "")
      signature <- sign(base, consumerSecret, tokenSecret)
    } yield signature
  }
}
