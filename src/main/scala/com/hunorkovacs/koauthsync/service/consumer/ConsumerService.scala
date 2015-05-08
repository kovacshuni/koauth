package com.hunorkovacs.koauthsync.service.consumer

import com.hunorkovacs.koauth.domain.KoauthRequest
import com.hunorkovacs.koauth.service.consumer.RequestWithInfo

import scala.concurrent.{Await, ExecutionContext}
import scala.concurrent.duration._

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

class DefaultConsumerService(private val ec: ExecutionContext) extends ConsumerService {

  private val asyncConsumer = new com.hunorkovacs.koauth.service.consumer.DefaultConsumerService(ec)

  override def createRequestTokenRequest(request: KoauthRequest,
                                         consumerKey: String,
                                         consumerSecret: String,
                                         callback: String): RequestWithInfo = {
    Await.result(asyncConsumer.createRequestTokenRequest(request, consumerKey, consumerSecret, callback), 2 seconds)
  }

  override def createAccessTokenRequest(request: KoauthRequest,
                                        consumerKey: String,
                                        consumerSecret: String,
                                        requestToken: String,
                                        requestTokenSecret: String,
                                        verifier: String): RequestWithInfo = {
    Await.result(asyncConsumer.createAccessTokenRequest(request, consumerKey, consumerSecret, requestToken,
      requestTokenSecret, verifier), 2 seconds)
  }

  override def createOauthenticatedRequest(request: KoauthRequest,
                                           consumerKey: String,
                                           consumerSecret: String,
                                           requestToken: String,
                                           requestTokenSecret: String): RequestWithInfo = {
    Await.result(asyncConsumer.createOauthenticatedRequest(request, consumerKey, consumerSecret, requestToken,
      requestTokenSecret), 2 seconds)
  }

  override def createGeneralSignedRequest(request: KoauthRequest): RequestWithInfo = {
    Await.result(asyncConsumer.createGeneralSignedRequest(request), 2 seconds)
  }
}
