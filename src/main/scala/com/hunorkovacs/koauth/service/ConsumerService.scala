package com.hunorkovacs.koauth.service

import com.hunorkovacs.koauth.domain.OauthRequest
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
                                (implicit ec: ExecutionContext)
}

abstract class DefaultConsumerService extends ConsumerService {

  def createGeneralSignedRequest(reqeust: OauthRequest, oauthParamsMap: Map[String, String])
                                (implicit ec: ExecutionContext) = {

  }
}

object ConsumerServiceFactory {

  def getDefaultConsumerService = throw NotImplementedException
}
