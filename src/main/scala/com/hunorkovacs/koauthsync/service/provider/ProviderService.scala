package com.hunorkovacs.koauthsync.service.provider

import org.slf4j.LoggerFactory

import scala.concurrent.{Await, ExecutionContext}
import scala.concurrent.duration._

trait ProviderService {

  def requestToken(request: KoauthRequest): KoauthResponse

  def accessToken(request: KoauthRequest): KoauthResponse

  def oauthenticate(request: KoauthRequest): Either[KoauthResponse, String]
}

protected class CustomProviderService(private val oauthVerifier: Verifier,
                                      private val persistence: Persistence,
                                      private val generator: TokenGenerator,
                                      private val ec: ExecutionContext) extends ProviderService {

  implicit private val implicitEc = ec
  private val logger = LoggerFactory.getLogger(classOf[CustomProviderService])
  private val asyncProvider = com.hunorkovacs.koauth.service.provider.ProviderService(oauthVerifier, persistence,
    generator, ec)

  override def requestToken(request: KoauthRequest): KoauthResponse = {
    Await.result(asyncProvider.requestToken(requestToken), 2 seconds)
  }

  override def accessToken(request: KoauthRequest): KoauthResponse = {
    Await.result(asyncProvider.accessToken(request), 2 seconds)
  }

  override def oauthenticate(request: KoauthRequest): Either[ResponseNok, String] = {
    Await.result(asyncProvider.oauthenticate(request), 2 seconds)
  }
}

object ProviderServiceFactory {

  private val logger = LoggerFactory.getLogger(ProviderServiceFactory.getClass)

  def createProviderService(persistence: Persistence, generator: TokenGenerator, ec: ExecutionContext): ProviderService = {
    logger.debug("Creating ProviderService with custom Persistence, TokenGenerator and ExecutionContext.")
    val verifier = new CustomVerifier(persistence, ec)
    new CustomProviderService(verifier, persistence, generator, ec)
  }

  def createProviderService(persistence: Persistence, ec: ExecutionContext): ProviderService = {
    logger.debug("Creating ProviderService with custom Persistence and ExecutionContext.")
    val verifier = new CustomVerifier(persistence, ec)
    new CustomProviderService(verifier, persistence, DefaultTokenGenerator, ec)
  }
}
