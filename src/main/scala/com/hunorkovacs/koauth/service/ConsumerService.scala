package com.hunorkovacs.koauth.service

import com.hunorkovacs.koauth.domain.OauthParams.{signatureName, tokenSecretName, consumerSecretName}
import com.hunorkovacs.koauth.domain.{OauthParams, EnhancedRequest, OauthRequest}
import com.hunorkovacs.koauth.service.DefaultOauthVerifier.sign
import com.hunorkovacs.koauth.service.OauthCombiner.{createAuthorizationHeader, concatItemsForSignature}
import com.hunorkovacs.koauth.service.OauthExtractor.enhanceRequest
import sun.reflect.generics.reflectiveObjects.NotImplementedException

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

  def createGeneralSignedRequest(reqeust: OauthRequest, oauthParamsMap: Map[String, String])
                                (implicit ec: ExecutionContext): Future[String]
}

abstract class DefaultConsumerService extends ConsumerService {

  def createGeneralSignedRequest(request: OauthRequest)
                                (implicit ec: ExecutionContext): Future[Either[String, String]] = {
    val enhancedRequestF = enhanceRequest(request)
    enhancedRequestF.flatMap(signRequest) flatMap {
      case Left(l) => successful(Left(l))
      case Right(signature) =>
        enhancedRequestF.map(request => (signatureName, signature) :: request.oauthParamsList)
          .flatMap(createAuthorizationHeader)
          .map(header => Right(header))
    }
  }

  def createSignatureBase(request: EnhancedRequest)
                         (implicit ec: ExecutionContext): Future[String] = concatItemsForSignature(request)

  def signRequest(request: EnhancedRequest)
                 (implicit ec: ExecutionContext): Future[Either[String, String]] = {
    Future {
      if (request.oauthParamsMap.contains(consumerSecretName)) Left("Can't sign without Conusmer Secret.")
      else {
        val consumerSecret = request.oauthParamsMap(consumerSecretName)
        val tokenSecret = request.oauthParamsMap.applyOrElse(tokenSecretName, x => "")
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
}

object ConsumerServiceFactory {

  def getDefaultConsumerService = throw NotImplementedException
}
