package com.hunorkovacs.koauth.service

import com.hunorkovacs.koauth.domain.OauthParams.{signatureName, tokenSecretName, consumerSecretName}
import com.hunorkovacs.koauth.domain.{EnhancedRequest, OauthRequest}
import com.hunorkovacs.koauth.service.DefaultOauthVerifier.sign
import com.hunorkovacs.koauth.service.OauthCombiner.{createAuthorizationHeader, concatItemsForSignature}

import scala.concurrent.Future.successful
import scala.concurrent.{ExecutionContext, Future}

trait ConsumerService {

  def createRequestTokenRequest(reqeust: OauthRequest, consumerKey: String, consumerSecret: String)
                               (implicit ec: ExecutionContext): Future[String]

  def createAuthorizeRequest(reqeust: OauthRequest, consumerKey: String, requestToken: String,
                             username: String, password: String)
                            (implicit ec: ExecutionContext): Future[String]

  def createAccessTokenRequest(reqeust: OauthRequest, consumerKey: String, consumerSecret: String,
                               requestToken: String, requestTokenSecret: String)
                              (implicit ec: ExecutionContext): Future[String]

  def createGeneralSignedRequest(request: EnhancedRequest)
                                (implicit ec: ExecutionContext): Future[Either[String, String]]
}

object DefaultConsumerService extends ConsumerService {

  val MessageMissingConsumerSecret= "Can't sign without Conusmer Secret."

  def createGeneralSignedRequest(request: EnhancedRequest)
                                (implicit ec: ExecutionContext): Future[Either[String, String]] = {
    signRequest(request) flatMap {
      case Left(l) => successful(Left(l))
      case Right(signature) =>
        Future(request.oauthParamsList
            .filterNot(param => consumerSecretName == param._1 || tokenSecretName == param._1)
            .::((signatureName, signature)))
          .flatMap(createAuthorizationHeader)
          .map(header => Right(header))
    }
  }

  def createSignatureBase(request: EnhancedRequest)
                         (implicit ec: ExecutionContext): Future[String] = {
    Future {
      val filteredList = request.oauthParamsList
        .filterNot(param => consumerSecretName == param._1 || tokenSecretName == param._1)
      new EnhancedRequest(request.method,
        request.urlWithoutParams,
        request.urlParams,
        request.bodyParams,
        filteredList,
        filteredList.toMap)
    }.flatMap(concatItemsForSignature)
  }

  def signRequest(request: EnhancedRequest)
                 (implicit ec: ExecutionContext): Future[Either[String, String]] = {
    Future {
      if (!request.oauthParamsMap.contains(consumerSecretName)) Left(MessageMissingConsumerSecret)
      else {
        val consumerSecret = request.oauthParamsMap(consumerSecretName)
        val tokenSecret = request.oauthParamsMap.applyOrElse(tokenSecretName, (s: String) => "")
        val signatureBaseF = createSignatureBase(request)
        Right((consumerSecret, tokenSecret, signatureBaseF))
      }
    } flatMap {
      case Left(l) => successful(Left(l))
      case Right(r) =>
        val (consumerSecret, tokenSecret, signatureBaseF) = r
        signatureBaseF.flatMap(b => sign(b, consumerSecret, tokenSecret))
          .map(s => Right(s))
    }
  }

  override def createRequestTokenRequest(reqeust: OauthRequest, consumerKey: String, consumerSecret: String)
                                        (implicit ec: ExecutionContext): Future[String] = ???

  override def createAccessTokenRequest(reqeust: OauthRequest, consumerKey: String, consumerSecret: String, requestToken: String, requestTokenSecret: String)
                                       (implicit ec: ExecutionContext): Future[String] = ???

  override def createAuthorizeRequest(reqeust: OauthRequest, consumerKey: String, requestToken: String, username: String, password: String)
                                     (implicit ec: ExecutionContext): Future[String] = ???
}
