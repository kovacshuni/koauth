package com.hunorkovacs.koauth.service.consumer

import com.hunorkovacs.koauth.domain.KoauthRequest

import scala.concurrent.{ExecutionContext, Future}

trait ConsumerService {

  def createRequestTokenRequest(request: KoauthRequest,
                                consumerKey: String,
                                consumerSecret: String,
                                callback: String): Future[RequestWithInfo]

  def createAccessTokenRequest(request: KoauthRequest,
                               consumerKey: String,
                               consumerSecret: String,
                               requestToken: String,
                               requestTokenSecret: String,
                               verifier: String): Future[RequestWithInfo]

  def createOauthenticatedRequest(request: KoauthRequest,
                                  consumerKey: String,
                                  consumerSecret: String,
                                  requestToken: String,
                                  requestTokenSecret: String): Future[RequestWithInfo]

  def createGeneralSignedRequest(request: KoauthRequest): Future[RequestWithInfo]
}

case class RequestWithInfo(request: KoauthRequest, signatureBase: String, header: String)


class DefaultConsumerService(private val ec: ExecutionContext) extends ConsumerService {

  implicit private val implicitEc = ec

  override def createRequestTokenRequest(request: KoauthRequest,
                                         consumerKey: String,
                                         consumerSecret: String,
                                         callback: String): Future[RequestWithInfo] = {
    Future {
      synch.ConsumerService.createRequestTokenRequest(request, consumerKey, consumerSecret, callback)
    }
  }

  override def createAccessTokenRequest(request: KoauthRequest,
                                        consumerKey: String,
                                        consumerSecret: String,
                                        requestToken: String,
                                        requestTokenSecret: String,
                                        verifier: String): Future[RequestWithInfo] = {
    Future {
      synch.ConsumerService.createAccessTokenRequest(request, consumerKey, consumerSecret, requestToken, requestTokenSecret, verifier)
    }
  }

  override def createOauthenticatedRequest(request: KoauthRequest,
                                           consumerKey: String,
                                           consumerSecret: String,
                                           requestToken: String,
                                           requestTokenSecret: String): Future[RequestWithInfo] = {
    Future {
      synch.ConsumerService.createOauthenticatedRequest(request, consumerKey, consumerSecret, requestToken, requestTokenSecret)
    }
  }

  def createGeneralSignedRequest(request: KoauthRequest): Future[RequestWithInfo] = {
    Future {
      synch.ConsumerService.createGeneralSignedRequest(request)
    }
  }
}



