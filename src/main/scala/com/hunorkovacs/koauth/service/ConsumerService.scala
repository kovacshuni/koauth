package com.hunorkovacs.koauth.service

import com.hunorkovacs.koauth.domain.OauthParams.{signatureName, tokenSecretName, consumerSecretName}
import com.hunorkovacs.koauth.domain.{OauthParams, EnhancedRequest, OauthRequest}
import com.hunorkovacs.koauth.service.DefaultOauthVerifier.sign
import com.hunorkovacs.koauth.service.OauthCombiner.{createAuthorizationHeader, concatItemsForSignature}
import com.hunorkovacs.koauth.service.OauthExtractor.enhanceRequest
import sun.reflect.generics.reflectiveObjects.NotImplementedException

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

  def createGeneralSignedRequest(request: OauthRequest, oauthParamsList: List[(String, String)])
                                (implicit ec: ExecutionContext): Future[String] = {
    val enhancedRequestF = enhanceRequest(request)
    val requestWithParamsF = enhancedRequestF.map(r => EnhancedRequest(r, oauthParamsList))
    val signatureBaseF = requestWithParamsF.flatMap(concatItemsForSignature)

    val consumerSecretF = requestWithParamsF.map(r => r.oauthParamsMap(consumerSecretName))
    val tokenSecretF = requestWithParamsF.map(r => r.oauthParamsMap(tokenSecretName))

    val signatureF = for {
      signatureBase <- signatureBaseF
      consumerSecret <- consumerSecretF
      tokenSecret <- tokenSecretF
      signature <- sign(signatureBase, consumerSecret, tokenSecret)
    } yield signature

    val paramsWithSignatureF = signatureF.map(s => (signatureName, s) :: oauthParamsList)

    val authHeaderF = paramsWithSignatureF.flatMap(createAuthorizationHeader)

    authHeaderF
  }
}

object ConsumerServiceFactory {

  def getDefaultConsumerService = throw NotImplementedException
}
